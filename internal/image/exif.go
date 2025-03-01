package image

import (
	"bytes"
	"encoding/binary"
	"image"
	"io"
)

// orientImage reads the image's exif data to find any orientation value, and
// returns an image that is rotated/mirrored appropriately.
func orientImage(src []byte, img image.Image) image.Image {
	switch parseOrientation(bytes.NewReader(src)) {
	case 2:
		return mirrorHorizontal(img)
	case 3:
		return rotate180(img)
	case 4:
		return mirrorVertical(img)
	case 5:
		return rotate270(mirrorHorizontal(img))
	case 6:
		return rotate90(img)
	case 7:
		return rotate90(mirrorHorizontal(img))
	case 8:
		return rotate270(img)
	default:
		return img
	}
}

// parseOrientation returns the exif orientation value from the provided image.
// If the image does not contain any exif data, or the data is invalid, it
// returns "0".
func parseOrientation(r io.Reader) int {
	// Read and verify the JPEG SOI marker.
	var marker uint16
	err := binary.Read(r, binary.BigEndian, &marker)
	if err != nil {
		return 0
	}
	if marker != 0xffd8 {
		return 0
	}

	// Read segments until we find the APP1 marker.
	buf := make([]byte, 1<<12)
	for {
		err = binary.Read(r, binary.BigEndian, &marker)
		if err != nil {
			return 0
		}

		var length uint16
		err = binary.Read(r, binary.BigEndian, &length)
		if err != nil {
			return 0
		}
		if length < 2 {
			// Invalid length.
			return 0
		}

		if marker == 0xffe1 {
			// APP1 marker.
			r = io.LimitReader(r, int64(length))
			break
		}

		err = discardBytes(r, buf, int64(length-2))
		if err != nil {
			return 0
		}
	}

	// Parse EXIF header.
	var exifHeader [6]byte
	_, err = io.ReadFull(r, exifHeader[:])
	if err != nil {
		return 0
	}
	if !bytes.Equal(exifHeader[:], []byte("Exif\x00\x00")) {
		// Not exif data.
		return 0
	}

	// Parse byte order marker.
	var orderMarker uint16
	err = binary.Read(r, binary.BigEndian, &orderMarker)
	if err != nil {
		return 0
	}

	var order binary.ByteOrder
	switch orderMarker {
	case 0x4d4d:
		order = binary.BigEndian
	case 0x4949:
		order = binary.LittleEndian
	default:
		return 0
	}

	// Verify TIFF header.
	var tiffHeader uint16
	err = binary.Read(r, order, &tiffHeader)
	if err != nil {
		return 0
	}
	if tiffHeader != 42 {
		// Invalid TIFF header.
		return 0
	}

	// Skip IFD offset.
	var ifdOffset uint32
	err = binary.Read(r, order, &ifdOffset)
	if err != nil {
		return 0
	}
	if ifdOffset < 8 {
		// Invalid IFD offset.
		return 0
	}
	err = discardBytes(r, buf, int64(ifdOffset-8))
	if err != nil {
		return 0
	}

	// Parse the number of directory entries.
	var numEntries uint16
	err = binary.Read(r, order, &numEntries)
	if err != nil {
		return 0
	}

	for range int(numEntries) {
		var tag uint16
		err = binary.Read(r, order, &tag)
		if err != nil {
			return 0
		}
		if tag != 0x0112 {
			// Not the orientation tag, skip.
			err = discardBytes(r, buf, 10)
			if err != nil {
				return 0
			}
			continue
		}

		err = discardBytes(r, buf, 6)
		if err != nil {
			return 0
		}

		var orientation uint16
		err = binary.Read(r, order, &orientation)
		if err != nil {
			return 0
		}
		if orientation < 1 || orientation > 8 {
			// Invalid orientation value.
			return 0
		}
		return int(orientation)
	}

	// No orientation tag found.
	return 0
}

func discardBytes(src io.Reader, buf []byte, n int64) error {
	written, err := io.CopyBuffer(io.Discard, io.LimitReader(src, n), buf)
	if written == n {
		return nil
	}
	if written < n && err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func rotate90(img image.Image) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	out := image.NewRGBA(image.Rect(0, 0, h, w))

	for y := range h {
		for x := range w {
			out.Set(h-y-1, x, img.At(x, y))
		}
	}
	return out
}

func rotate180(img image.Image) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	out := image.NewRGBA(bounds)

	for y := range h {
		for x := range w {
			out.Set(w-x-1, h-y-1, img.At(x, y))
		}
	}
	return out
}

func rotate270(img image.Image) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	out := image.NewRGBA(image.Rect(0, 0, h, w))

	for y := range h {
		for x := range w {
			out.Set(y, w-x-1, img.At(x, y))
		}
	}
	return out
}

func mirrorHorizontal(img image.Image) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	out := image.NewRGBA(bounds)

	for y := range h {
		for x := range w {
			out.Set(w-x-1, y, img.At(x, y))
		}
	}
	return out
}

func mirrorVertical(img image.Image) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	out := image.NewRGBA(bounds)

	for y := range h {
		for x := range w {
			out.Set(x, h-y-1, img.At(x, y))
		}
	}
	return out
}
