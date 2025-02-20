package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/printer"
	"github.com/ryanfowler/fetch/internal/vars"
)

func Update(ctx context.Context, p *printer.Printer, timeout time.Duration) bool {
	err := update(ctx, p, timeout)
	if err == nil {
		return true
	}

	p.Set(printer.Bold)
	p.Set(printer.Red)
	p.WriteString("info: ")
	p.Reset()
	p.WriteString(err.Error())
	p.WriteString("\n")
	p.Flush(os.Stderr)
	return false
}

func update(ctx context.Context, p *printer.Printer, timeout time.Duration) error {
	cfg := client.ClientConfig{Timeout: timeout}
	c := client.NewClient(cfg)

	writeInfo(p, "fetching latest release tag")
	latest, err := getLatestTag(ctx, c)
	if err != nil {
		return err
	}

	if strings.TrimPrefix(latest, "v") == vars.Version {
		p.WriteString("\n  currently using the latest version (v")
		p.WriteString(vars.Version)
		p.WriteString(")\n")
		p.Flush(os.Stderr)
		return nil
	}

	writeInfo(p, fmt.Sprintf("downloading latest version (%s)", latest))
	rc, err := getArtifactReader(ctx, c, latest)
	if err != nil {
		return err
	}
	defer rc.Close()

	tempDir, err := os.MkdirTemp("", "fetch-")
	if err != nil {
		return err
	}
	err = unpackArtifact(tempDir, rc)
	if err != nil {
		return err
	}

	binPath, err := getExecutablePath()
	if err != nil {
		return err
	}
	src := filepath.Join(tempDir, getFetchFilename())
	err = os.Rename(src, binPath)
	if err != nil {
		return err
	}

	p.WriteString("\n  fetch successfully updated (v")
	p.WriteString(vars.Version)
	p.WriteString(" -> ")
	p.WriteString(latest)
	p.WriteString(")\n")
	p.Flush(os.Stderr)
	return nil
}

func getLatestTag(ctx context.Context, c *client.Client) (string, error) {
	type Release struct {
		TagName string `json:"tag_name"`
	}

	u, err := url.Parse("https://api.github.com/repos/ryanfowler/fetch/releases/latest")
	if err != nil {
		return "", err
	}

	cfg := client.RequestConfig{
		Method: "GET",
		URL:    u,
	}
	req, err := c.NewRequest(ctx, cfg)
	if err != nil {
		return "", err
	}

	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetching latest release: received status: %d", resp.StatusCode)
	}

	var release Release
	err = json.NewDecoder(resp.Body).Decode(&release)
	if err != nil {
		return "", err
	}

	return release.TagName, nil
}

func getArtifactReader(ctx context.Context, c *client.Client, tag string) (io.ReadCloser, error) {
	urlStr := fmt.Sprintf("https://github.com/ryanfowler/fetch/releases/download/%s/fetch-%s-%s-%s.tar.gz",
		tag, tag, runtime.GOOS, runtime.GOARCH)
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	cfg := client.RequestConfig{
		Method: "GET",
		URL:    u,
	}
	req, err := c.NewRequest(ctx, cfg)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("downloading artifact: received status: %d", resp.StatusCode)
	}

	return resp.Body, nil
}

func getExecutablePath() (string, error) {
	binPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(binPath)
}

func getFetchFilename() string {
	name := "fetch"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func writeInfo(p *printer.Printer, s string) {
	p.Set(printer.Bold)
	p.Set(printer.Green)
	p.WriteString("info: ")
	p.Reset()

	p.WriteString(s)
	p.WriteString("\n")
	p.Flush(os.Stderr)
}
