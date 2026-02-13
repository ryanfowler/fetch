package update

import (
	"io"
	"strings"

	"github.com/ryanfowler/fetch/internal/core"
	"github.com/ryanfowler/fetch/internal/progress"
)

// updateProgress wraps an io.ReadCloser and displays a progress bar to stderr.
type updateProgress struct {
	bar     *progress.Bar
	rc      io.ReadCloser
	printer *core.Printer
}

func newUpdateProgress(rc io.ReadCloser, p *core.Printer, totalBytes int64) *updateProgress {
	return &updateProgress{
		bar:     progress.NewBar(rc, p, totalBytes, nil),
		rc:      rc,
		printer: p,
	}
}

func (up *updateProgress) Read(p []byte) (int, error) {
	return up.bar.Read(p)
}

func (up *updateProgress) Close() error {
	err := up.rc.Close()
	up.bar.Stop()
	clearLine(up.printer, 60)
	return err
}

// updateSpinner wraps an io.ReadCloser and displays a bouncing spinner to stderr.
type updateSpinner struct {
	spinner *progress.Spinner
	rc      io.ReadCloser
	printer *core.Printer
}

func newUpdateSpinner(rc io.ReadCloser, p *core.Printer) *updateSpinner {
	return &updateSpinner{
		spinner: progress.NewSpinner(rc, p, nil),
		rc:      rc,
		printer: p,
	}
}

func (us *updateSpinner) Read(p []byte) (int, error) {
	return us.spinner.Read(p)
}

func (us *updateSpinner) Close() error {
	err := us.rc.Close()
	us.spinner.Stop()
	clearLine(us.printer, 40)
	return err
}

func clearLine(p *core.Printer, width int) {
	p.WriteString("\r")
	p.WriteString(strings.Repeat(" ", width))
	p.WriteString("\r")
	p.Flush()
}
