package steganography

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// fixedEnvelopeKey is the fixed key used by the envelope tests.
var fixedEnvelopeKey = []byte("correct horse battery staple")

// fixedEnvelopeMessage is the fixed payload used by the envelope tests.
var fixedEnvelopeMessage = []byte("The quadrupedal Stegosaurus hides its secrets between the pixels.")

// fixedEnvelopeImage builds a deterministic 64x64 NRGBA test image.
func fixedEnvelopeImage() *image.NRGBA {
	width, height := 64, 64
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.SetNRGBA(x, y, color.NRGBA{
				R: uint8((x*3 + y*5) % 256),
				G: uint8((x*7 + y*11) % 256),
				B: uint8((x*13 + y*17) % 256),
				A: uint8(128 + (x+y)%128),
			})
		}
	}
	return img
}

// decodePNG decodes a PNG buffer back into an image.
func decodePNG(t *testing.T, buf *bytes.Buffer) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("failed to decode encoded PNG: %v", err)
	}
	return img
}

func TestEnvelopeRoundTripWithKey(t *testing.T) {
	w := new(bytes.Buffer)
	if err := EncodeEnvelope(w, fixedEnvelopeImage(), fixedEnvelopeMessage, fixedEnvelopeKey); err != nil {
		t.Fatalf("EncodeEnvelope failed: %v", err)
	}

	msg, err := DecodeEnvelope(decodePNG(t, w), fixedEnvelopeKey)
	if err != nil {
		t.Fatalf("DecodeEnvelope failed: %v", err)
	}
	if !bytes.Equal(msg, fixedEnvelopeMessage) {
		t.Fatalf("messages don't match:\ngot  %q\nwant %q", msg, fixedEnvelopeMessage)
	}
}

func TestEnvelopeRoundTripWithoutKey(t *testing.T) {
	w := new(bytes.Buffer)
	if err := EncodeEnvelope(w, fixedEnvelopeImage(), fixedEnvelopeMessage, nil); err != nil {
		t.Fatalf("EncodeEnvelope failed: %v", err)
	}

	msg, err := DecodeEnvelope(decodePNG(t, w), nil)
	if err != nil {
		t.Fatalf("DecodeEnvelope failed: %v", err)
	}
	if !bytes.Equal(msg, fixedEnvelopeMessage) {
		t.Fatalf("messages don't match:\ngot  %q\nwant %q", msg, fixedEnvelopeMessage)
	}
}

func TestEnvelopeRepeatable(t *testing.T) {
	first := new(bytes.Buffer)
	if err := EncodeEnvelope(first, fixedEnvelopeImage(), fixedEnvelopeMessage, fixedEnvelopeKey); err != nil {
		t.Fatalf("first EncodeEnvelope failed: %v", err)
	}
	second := new(bytes.Buffer)
	if err := EncodeEnvelope(second, fixedEnvelopeImage(), fixedEnvelopeMessage, fixedEnvelopeKey); err != nil {
		t.Fatalf("second EncodeEnvelope failed: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("encoding the same image, message and key twice produced different output")
	}
}

func TestEnvelopeKeyChangesOutput(t *testing.T) {
	withKey := new(bytes.Buffer)
	if err := EncodeEnvelope(withKey, fixedEnvelopeImage(), fixedEnvelopeMessage, fixedEnvelopeKey); err != nil {
		t.Fatalf("EncodeEnvelope with key failed: %v", err)
	}
	withoutKey := new(bytes.Buffer)
	if err := EncodeEnvelope(withoutKey, fixedEnvelopeImage(), fixedEnvelopeMessage, nil); err != nil {
		t.Fatalf("EncodeEnvelope without key failed: %v", err)
	}
	if bytes.Equal(withKey.Bytes(), withoutKey.Bytes()) {
		t.Fatal("key-scrambled and plain encodings are identical")
	}
}

func TestEnvelopeWrongKey(t *testing.T) {
	w := new(bytes.Buffer)
	if err := EncodeEnvelope(w, fixedEnvelopeImage(), fixedEnvelopeMessage, fixedEnvelopeKey); err != nil {
		t.Fatalf("EncodeEnvelope failed: %v", err)
	}
	img := decodePNG(t, w)

	if _, err := DecodeEnvelope(img, []byte("the wrong key")); err != ErrWrongKey {
		t.Fatalf("expected ErrWrongKey, got %v", err)
	}
	if _, err := DecodeEnvelope(img, nil); err != ErrKeyRequired {
		t.Fatalf("expected ErrKeyRequired, got %v", err)
	}
}

func TestEnvelopeTamperedPixel(t *testing.T) {
	img := fixedEnvelopeImage()
	// Fill the image to capacity so every payload slot is used and any
	// payload-region tamper is guaranteed to corrupt the message.
	message := make([]byte, MaxEnvelopePayloadSize(img))
	for i := range message {
		message[i] = uint8(i * 31)
	}

	w := new(bytes.Buffer)
	if err := EncodeEnvelopeNRGBA(w, img, message, fixedEnvelopeKey); err != nil {
		t.Fatalf("EncodeEnvelopeNRGBA failed: %v", err)
	}

	tampered, err := png.Decode(bytes.NewReader(w.Bytes()))
	if err != nil {
		t.Fatalf("failed to decode encoded PNG: %v", err)
	}
	nrgba := imageToNRGBA(tampered)

	// Flip the red LSB of the bottom-right pixel (payload region, far from
	// the 40-pixel header in the first column).
	c := nrgba.NRGBAAt(63, 63)
	c.R ^= 1
	nrgba.SetNRGBA(63, 63, c)

	if _, err := DecodeEnvelopeNRGBA(nrgba, fixedEnvelopeKey); err != ErrChecksumMismatch {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestEnvelopeTruncatedImage(t *testing.T) {
	// Payload larger than the cropped image can hold (cropped capacity is
	// (32*64*3-120)/8 = 753 bytes), so the declared length cannot fit.
	message := make([]byte, 1000)
	for i := range message {
		message[i] = uint8(i * 31)
	}
	img := fixedEnvelopeImage()
	w := new(bytes.Buffer)
	if err := EncodeEnvelopeNRGBA(w, img, message, fixedEnvelopeKey); err != nil {
		t.Fatalf("EncodeEnvelopeNRGBA failed: %v", err)
	}
	decoded, err := png.Decode(bytes.NewReader(w.Bytes()))
	if err != nil {
		t.Fatalf("failed to decode encoded PNG: %v", err)
	}
	full := imageToNRGBA(decoded)

	// Crop the right half of the image (as if an edge was cut off). The
	// header lives in the first column, so it survives, but the declared
	// payload no longer fits.
	cropped := image.NewNRGBA(image.Rect(0, 0, 32, 64))
	for x := 0; x < 32; x++ {
		for y := 0; y < 64; y++ {
			cropped.SetNRGBA(x, y, full.NRGBAAt(x, y))
		}
	}

	if _, err := DecodeEnvelopeNRGBA(cropped, fixedEnvelopeKey); err != ErrTruncatedImage {
		t.Fatalf("expected ErrTruncatedImage, got %v", err)
	}
}

func TestEnvelopeEmptyMessage(t *testing.T) {
	w := new(bytes.Buffer)
	if err := EncodeEnvelope(w, fixedEnvelopeImage(), nil, fixedEnvelopeKey); err != ErrEmptyMessage {
		t.Fatalf("expected ErrEmptyMessage, got %v", err)
	}
	if err := EncodeEnvelope(w, fixedEnvelopeImage(), []byte{}, fixedEnvelopeKey); err != ErrEmptyMessage {
		t.Fatalf("expected ErrEmptyMessage, got %v", err)
	}
}

func TestEnvelopeMessageTooLargeLeavesImageUntouched(t *testing.T) {
	img := fixedEnvelopeImage()
	snapshot := make([]byte, len(img.Pix))
	copy(snapshot, img.Pix)

	tooBig := make([]byte, MaxEnvelopePayloadSize(img)+1)
	w := new(bytes.Buffer)
	if err := EncodeEnvelopeNRGBA(w, img, tooBig, fixedEnvelopeKey); err != ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
	if w.Len() != 0 {
		t.Fatal("failed encode wrote to the output buffer")
	}
	if !bytes.Equal(snapshot, img.Pix) {
		t.Fatal("failed encode left a half-written image")
	}
}

func TestEnvelopePreservesDimensionsAndAlpha(t *testing.T) {
	img := fixedEnvelopeImage()
	bounds := img.Bounds()
	alphas := make([]uint8, 0, bounds.Dx()*bounds.Dy())
	for x := 0; x < bounds.Dx(); x++ {
		for y := 0; y < bounds.Dy(); y++ {
			alphas = append(alphas, img.NRGBAAt(x, y).A)
		}
	}

	w := new(bytes.Buffer)
	if err := EncodeEnvelopeNRGBA(w, img, fixedEnvelopeMessage, fixedEnvelopeKey); err != nil {
		t.Fatalf("EncodeEnvelopeNRGBA failed: %v", err)
	}

	if img.Bounds() != bounds {
		t.Fatalf("image dimensions changed: %v -> %v", bounds, img.Bounds())
	}
	i := 0
	for x := 0; x < bounds.Dx(); x++ {
		for y := 0; y < bounds.Dy(); y++ {
			if img.NRGBAAt(x, y).A != alphas[i] {
				t.Fatalf("alpha changed at (%d,%d)", x, y)
			}
			i++
		}
	}
}

func TestEnvelopeNotDetectedInLegacyOrPlainImages(t *testing.T) {
	// Legacy length-prefixed encoding must not be misidentified as an envelope.
	legacy := new(bytes.Buffer)
	if err := Encode(legacy, fixedEnvelopeImage(), fixedEnvelopeMessage); err != nil {
		t.Fatalf("legacy Encode failed: %v", err)
	}
	legacyImg := decodePNG(t, legacy)
	if HasEnvelope(legacyImg) {
		t.Fatal("legacy-encoded image misidentified as envelope")
	}
	if _, err := DecodeEnvelope(legacyImg, nil); err != ErrNoEnvelope {
		t.Fatalf("expected ErrNoEnvelope for legacy image, got %v", err)
	}

	// A plain image carries no envelope either.
	if HasEnvelope(fixedEnvelopeImage()) {
		t.Fatal("plain image misidentified as envelope")
	}
	if _, err := DecodeEnvelope(fixedEnvelopeImage(), nil); err != ErrNoEnvelope {
		t.Fatalf("expected ErrNoEnvelope for plain image, got %v", err)
	}

	// And the legacy reader must still read the legacy encoding.
	sizeOfMessage := GetMessageSizeFromImage(legacyImg)
	if msg := Decode(sizeOfMessage, legacyImg); !bytes.Equal(msg, fixedEnvelopeMessage) {
		t.Fatal("legacy Decode failed on legacy-encoded image")
	}
}

func TestEnvelopeDetectedAfterEncode(t *testing.T) {
	w := new(bytes.Buffer)
	if err := EncodeEnvelope(w, fixedEnvelopeImage(), fixedEnvelopeMessage, fixedEnvelopeKey); err != nil {
		t.Fatalf("EncodeEnvelope failed: %v", err)
	}
	if !HasEnvelope(decodePNG(t, w)) {
		t.Fatal("envelope not detected in envelope-encoded image")
	}
}

func TestEnvelopeTinyImage(t *testing.T) {
	tiny := image.NewNRGBA(image.Rect(0, 0, 4, 4)) // 48 slots < 120 header bits
	w := new(bytes.Buffer)
	if err := EncodeEnvelopeNRGBA(w, tiny, []byte{1}, nil); err != ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
	if _, err := DecodeEnvelopeNRGBA(tiny, nil); err != ErrNoEnvelope {
		t.Fatalf("expected ErrNoEnvelope, got %v", err)
	}
}
