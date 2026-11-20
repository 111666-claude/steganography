package steganography

import (
	"bytes"
	"errors"
	"hash/crc32"
	"hash/fnv"
	"image"
	"image/png"
	"math/rand"
)

// Envelope format (self-describing, integrity-checked wrapper around a payload):
//
//	header (15 bytes = 120 bits = exactly 40 pixels), always in legacy scan order:
//	  magic     4 bytes  "STEG"           - identifies the envelope
//	  version   1 byte   currently 1
//	  keyHint   1 byte   top byte of the FNV-1a hash of the key (0 if none)
//	  flags     1 byte   bit 0: payload pixel order is scrambled with a key
//	  length    4 bytes  payload length in bytes (big endian)
//	  crc32     4 bytes  IEEE checksum of the payload (big endian)
//	payload: length bytes, embedded right after the header, in a pixel order
//	that is optionally permuted by a key-seeded Fisher-Yates shuffle.
//
// The header is never scrambled, so a reader can always detect the envelope,
// validate the key and learn the payload length without knowing the key.
// A legacy length-prefixed message cannot be mistaken for an envelope: its
// first four bytes are a message length, and a length of 0x53544547 ("STEG")
// would exceed any image's capacity.

const (
	envelopeVersion       = 1
	envelopeHeaderLen     = 15 // bytes
	envelopeHeaderBits    = envelopeHeaderLen * 8
	envelopeFlagScrambled = 1
)

var envelopeMagic = []byte{'S', 'T', 'E', 'G'}

// Errors returned by the envelope encoder and decoder.
var (
	ErrEmptyMessage       = errors.New("steganography: message is empty")
	ErrMessageTooLarge    = errors.New("steganography: message too large for image")
	ErrNoEnvelope         = errors.New("steganography: no data envelope found in image")
	ErrUnsupportedVersion = errors.New("steganography: unsupported envelope version or flags")
	ErrKeyRequired        = errors.New("steganography: envelope requires a key")
	ErrWrongKey           = errors.New("steganography: wrong key for envelope")
	ErrTruncatedImage     = errors.New("steganography: image too small for declared message (truncated?)")
	ErrChecksumMismatch   = errors.New("steganography: checksum mismatch, data corrupted or tampered")
)

// EncodeEnvelope encodes a message into the input image wrapped in a
// self-describing, checksummed envelope. If key is non-empty, the payload
// pixel positions are scrambled with a permutation derived from the key.
// It wraps EncodeEnvelopeNRGBA making the conversion from image.Image to image.NRGBA.
/*
	Input:
		writeBuffer *bytes.Buffer : the destination of the encoded image bytes
		pictureInputFile image.Image : image data used in encoding
		message []byte : byte slice of the message to be encoded
		key []byte : optional key driving the pixel position scrambling (nil for none)
	Output:
		bytes buffer ( io.writter ) to create file, or send data.
*/
func EncodeEnvelope(writeBuffer *bytes.Buffer, pictureInputFile image.Image, message []byte, key []byte) error {
	rgbImage := imageToNRGBA(pictureInputFile)
	return EncodeEnvelopeNRGBA(writeBuffer, rgbImage, message, key)
}

// EncodeEnvelopeNRGBA encodes a message into the input image wrapped in a
// self-describing, checksummed envelope, using least significant bit
// steganography. If key is non-empty, the payload pixel positions are
// scrambled with a permutation derived from the key.
// The image dimensions and alpha channel are never modified. Capacity is
// checked before any pixel is touched, so a failed encode never leaves a
// half-written image.
/*
	Input:
		writeBuffer *bytes.Buffer : the destination of the encoded image bytes
		rgbImage *image.NRGBA : image data used in encoding
		message []byte : byte slice of the message to be encoded
		key []byte : optional key driving the pixel position scrambling (nil for none)
	Output:
		bytes buffer ( io.writter ) to create file, or send data.
*/
func EncodeEnvelopeNRGBA(writeBuffer *bytes.Buffer, rgbImage *image.NRGBA, message []byte, key []byte) error {
	if len(message) == 0 {
		return ErrEmptyMessage
	}
	if uint64(len(message)) > 0xFFFFFFFF {
		return ErrMessageTooLarge
	}

	width := rgbImage.Bounds().Dx()
	height := rgbImage.Bounds().Dy()

	// Capacity pre-check: no pixel is modified before this succeeds.
	totalSlots := width * height * 3
	if envelopeHeaderBits+len(message)*8 > totalSlots {
		return ErrMessageTooLarge
	}

	writeBits(rgbImage, height, sequentialSlots(0, envelopeHeaderBits), buildEnvelopeHeader(message, key))
	writeBits(rgbImage, height, payloadSlots(envelopeHeaderBits, totalSlots, key), message)

	return png.Encode(writeBuffer, rgbImage)
}

// DecodeEnvelope extracts and verifies an envelope payload from a picture.
// It detects the envelope automatically; images carrying only a legacy
// length-prefixed message (or no message at all) return ErrNoEnvelope.
// The key must match the one given to EncodeEnvelope (nil if none was used).
/*
	Input:
		pictureInputFile image.Image : image data used in decoding
		key []byte : optional key used when encoding (nil for none)
	Output:
		message []byte decoded from image
*/
func DecodeEnvelope(pictureInputFile image.Image, key []byte) (message []byte, err error) {
	rgbImage := imageToNRGBA(pictureInputFile)
	return DecodeEnvelopeNRGBA(rgbImage, key)
}

// DecodeEnvelopeNRGBA extracts and verifies an envelope payload from an NRGBA image.
// It detects the envelope automatically; images carrying only a legacy
// length-prefixed message (or no message at all) return ErrNoEnvelope.
// The key must match the one given to EncodeEnvelopeNRGBA (nil if none was used).
/*
	Input:
		rgbImage *image.NRGBA : image data used in decoding
		key []byte : optional key used when encoding (nil for none)
	Output:
		message []byte decoded from image
*/
func DecodeEnvelopeNRGBA(rgbImage *image.NRGBA, key []byte) (message []byte, err error) {
	width := rgbImage.Bounds().Dx()
	height := rgbImage.Bounds().Dy()
	totalSlots := width * height * 3

	if totalSlots < envelopeHeaderBits {
		return nil, ErrNoEnvelope
	}

	header := readBits(rgbImage, height, sequentialSlots(0, envelopeHeaderBits), envelopeHeaderLen)

	if !bytes.Equal(header[0:4], envelopeMagic) {
		return nil, ErrNoEnvelope
	}
	if header[4] != envelopeVersion || header[6]&^byte(envelopeFlagScrambled) != 0 {
		return nil, ErrUnsupportedVersion
	}
	scrambled := header[6]&envelopeFlagScrambled != 0
	if scrambled {
		if len(key) == 0 {
			return nil, ErrKeyRequired
		}
		if header[5] != envelopeKeyHint(key) {
			return nil, ErrWrongKey
		}
	}

	msgLen := combineToInt(header[7], header[8], header[9], header[10])
	expectedCRC := combineToInt(header[11], header[12], header[13], header[14])

	if msgLen == 0 {
		return nil, ErrChecksumMismatch
	}
	if uint64(msgLen) > uint64(totalSlots-envelopeHeaderBits)/8 {
		return nil, ErrTruncatedImage
	}

	payload := readBits(rgbImage, height, payloadSlots(envelopeHeaderBits, totalSlots, key), int(msgLen))

	if crc32.ChecksumIEEE(payload) != expectedCRC {
		return nil, ErrChecksumMismatch
	}
	return payload, nil
}

// HasEnvelope reports whether the image carries a data envelope.
func HasEnvelope(pictureInputFile image.Image) bool {
	rgbImage := imageToNRGBA(pictureInputFile)
	width := rgbImage.Bounds().Dx()
	height := rgbImage.Bounds().Dy()
	if width*height*3 < envelopeHeaderBits {
		return false
	}
	header := readBits(rgbImage, height, sequentialSlots(0, 4*8), 4)
	return bytes.Equal(header, envelopeMagic)
}

// MaxEnvelopePayloadSize returns how many payload bytes fit in the image
// when using the envelope encoding.
func MaxEnvelopePayloadSize(img image.Image) uint32 {
	width := img.Bounds().Dx()
	height := img.Bounds().Dy()
	eval := (width*height*3 - envelopeHeaderBits) / 8
	if eval < 0 {
		eval = 0
	}
	return uint32(eval)
}

// buildEnvelopeHeader assembles the 15-byte envelope header for a payload.
func buildEnvelopeHeader(message []byte, key []byte) []byte {
	header := make([]byte, envelopeHeaderLen)
	copy(header[0:4], envelopeMagic)
	header[4] = envelopeVersion
	if len(key) > 0 {
		header[5] = envelopeKeyHint(key)
		header[6] = envelopeFlagScrambled
	}
	one, two, three, four := splitToBytes(uint32(len(message)))
	header[7], header[8], header[9], header[10] = one, two, three, four
	one, two, three, four = splitToBytes(crc32.ChecksumIEEE(message))
	header[11], header[12], header[13], header[14] = one, two, three, four
	return header
}

// envelopeKeySeed derives a PRNG seed from a key.
func envelopeKeySeed(key []byte) int64 {
	h := fnv.New64a()
	h.Write(key)
	return int64(h.Sum64())
}

// envelopeKeyHint is a non-cryptographic key fingerprint stored in the
// header so a wrong key is rejected before the payload is read.
func envelopeKeyHint(key []byte) byte {
	return byte(uint64(envelopeKeySeed(key)) >> 56)
}

// sequentialSlots returns slot indexes [start, start+count).
func sequentialSlots(start, count int) []int {
	slots := make([]int, count)
	for i := range slots {
		slots[i] = start + i
	}
	return slots
}

// payloadSlots returns the slot indexes available for the payload
// (all slots from start to total), permuted with a key-seeded
// Fisher-Yates shuffle when key is non-empty.
func payloadSlots(start, total int, key []byte) []int {
	slots := sequentialSlots(start, total-start)
	if len(key) > 0 {
		r := rand.New(rand.NewSource(envelopeKeySeed(key)))
		r.Shuffle(len(slots), func(i, j int) {
			slots[i], slots[j] = slots[j], slots[i]
		})
	}
	return slots
}

// slotToXYChannel maps a slot index to a pixel and color channel,
// following the legacy column-major scan order (x outer, y inner, R,G,B).
func slotToXYChannel(slot, height int) (x, y, channel int) {
	pixel := slot / 3
	channel = slot % 3
	x = pixel / height
	y = pixel % height
	return
}

// writeBits embeds data bit by bit (MSB first) into the LSBs of the given slots.
func writeBits(rgbImage *image.NRGBA, height int, slots []int, data []byte) {
	slotIndex := 0
	for _, b := range data {
		for bitIndex := 0; bitIndex < 8; bitIndex++ {
			x, y, channel := slotToXYChannel(slots[slotIndex], height)
			c := rgbImage.NRGBAAt(x, y)
			bit := getBitFromByte(b, bitIndex)
			switch channel {
			case 0:
				setLSB(&c.R, bit)
			case 1:
				setLSB(&c.G, bit)
			case 2:
				setLSB(&c.B, bit)
			}
			rgbImage.SetNRGBA(x, y, c)
			slotIndex++
		}
	}
}

// readBits reads numBytes bytes bit by bit (MSB first) from the LSBs of the given slots.
func readBits(rgbImage *image.NRGBA, height int, slots []int, numBytes int) []byte {
	out := make([]byte, numBytes)
	var byteIndex, bitIndex uint32
	for i := 0; i < numBytes*8; i++ {
		x, y, channel := slotToXYChannel(slots[i], height)
		c := rgbImage.NRGBAAt(x, y)
		var lsb byte
		switch channel {
		case 0:
			lsb = getLSB(c.R)
		case 1:
			lsb = getLSB(c.G)
		case 2:
			lsb = getLSB(c.B)
		}
		out[byteIndex] = setBitInByte(out[byteIndex], bitIndex, lsb)
		bitIndex++
		if bitIndex > 7 {
			bitIndex = 0
			byteIndex++
		}
	}
	return out
}
