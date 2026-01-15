package multipart

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
)

// Multipart implements io.Reader for multipart data.
type Multipart struct {
	io.Reader
	contentType string
}

// NewMultipart returns a Multipart using the provided key/values.
func NewMultipart(kvs []core.KeyVal) *Multipart {
	if len(kvs) == 0 {
		return nil
	}

	// Create a pipe and asynchronously write to it in a goroutine.
	reader, writer := io.Pipe()
	mpw := multipart.NewWriter(writer)
	go func() {
		defer func() {
			mpw.Close()
			writer.Close()
		}()

		for _, kv := range kvs {
			if !strings.HasPrefix(kv.Val, "@") {
				err := mpw.WriteField(kv.Key, kv.Val)
				if err != nil {
					writer.CloseWithError(err)
					return
				}
				continue
			}

			// Form part is a file.
			err := writeFilePart(mpw, kv.Key, kv.Val[1:])
			if err != nil {
				writer.CloseWithError(err)
				return
			}
		}
	}()

	return &Multipart{
		Reader:      reader,
		contentType: mpw.FormDataContentType(),
	}
}

// ContentType returns the Content-Type header value to use for this request.
func (m *Multipart) ContentType() string {
	return m.contentType
}

// writes the multipart file part and returns any error encountered.
func writeFilePart(mpw *multipart.Writer, key, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	ct := detectTypeByExtension(filename)
	if ct == "" {
		// Unable to detect MIME type by extension, try from raw bytes.
		sniff := make([]byte, 512)
		n, err := f.Read(sniff)
		if err != nil && err != io.EOF {
			return err
		}

		ct = http.DetectContentType(sniff[:n])
		r = io.MultiReader(bytes.NewReader(sniff[:n]), f)
	}

	headers := textproto.MIMEHeader{}
	headers.Set("Content-Disposition", multipart.FileContentDisposition(key, filename))
	headers.Set("Content-Type", ct)

	w, err := mpw.CreatePart(headers)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, r)
	return err
}

func detectTypeByExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		return ""
	}

	switch ext {
	// Images
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".avif":
		return "image/avif"
	case ".heic", ".heif":
		return "image/heif"
	case ".jxl":
		return "image/jxl"
	case ".tif", ".tiff":
		return "image/tiff"
	case ".bmp":
		return "image/bmp"
	case ".ico":
		return "image/x-icon"
	case ".svg":
		return "image/svg+xml"
	case ".psd":
		return "image/vnd.adobe.photoshop"
	case ".raw", ".dng", ".nef", ".cr2", ".arw":
		return "image/x-raw"

	// Video
	case ".mp4":
		return "video/mp4"
	case ".m4v":
		return "video/x-m4v"
	case ".webm":
		return "video/webm"
	case ".mov":
		return "video/quicktime"
	case ".mkv":
		return "video/x-matroska"
	case ".avi":
		return "video/x-msvideo"
	case ".wmv":
		return "video/x-ms-wmv"
	case ".flv":
		return "video/x-flv"
	case ".mpeg", ".mpg":
		return "video/mpeg"
	case ".ogv":
		return "video/ogg"

	// Audio
	case ".mp3":
		return "audio/mpeg"
	case ".m4a":
		return "audio/mp4"
	case ".aac":
		return "audio/aac"
	case ".wav":
		return "audio/wav"
	case ".flac":
		return "audio/flac"
	case ".ogg":
		return "audio/ogg"
	case ".opus":
		return "audio/opus"
	case ".aiff", ".aif":
		return "audio/aiff"
	case ".mid", ".midi":
		return "audio/midi"

	// Documents
	case ".pdf":
		return "application/pdf"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".csv":
		return "text/csv; charset=utf-8"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".md":
		return "text/markdown; charset=utf-8"
	case ".rtf":
		return "application/rtf"

	// Office formats
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xls":
		return "application/vnd.ms-excel"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".ppt":
		return "application/vnd.ms-powerpoint"
	case ".pptx":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"

	// Fonts
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".otf":
		return "font/otf"
	case ".eot":
		return "application/vnd.ms-fontobject"

	// Archives
	case ".zip":
		return "application/zip"
	case ".tar":
		return "application/x-tar"
	case ".gz":
		return "application/gzip"
	case ".tgz":
		return "application/gzip"
	case ".bz2":
		return "application/x-bzip2"
	case ".xz":
		return "application/x-xz"
	case ".7z":
		return "application/x-7z-compressed"
	case ".rar":
		return "application/vnd.rar"

	// Executables / binaries
	case ".exe":
		return "application/vnd.microsoft.portable-executable"
	case ".msi":
		return "application/x-msi"
	case ".deb":
		return "application/vnd.debian.binary-package"
	case ".rpm":
		return "application/x-rpm"

	// Scripts / code
	case ".js":
		return "application/javascript"
	case ".mjs":
		return "application/javascript"
	case ".ts":
		return "application/typescript"
	case ".go":
		return "text/x-go; charset=utf-8"
	case ".rs":
		return "text/x-rust; charset=utf-8"
	case ".py":
		return "text/x-python; charset=utf-8"
	case ".sh":
		return "application/x-sh"

	default:
		return ""
	}
}
