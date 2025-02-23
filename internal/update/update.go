package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/client"
	"github.com/ryanfowler/fetch/internal/printer"
)

func Update(ctx context.Context, p *printer.Printer, timeout time.Duration, version string) bool {
	err := update(ctx, p, timeout, version)
	if err == nil {
		return true
	}

	p.Set(printer.Bold)
	p.Set(printer.Red)
	p.WriteString("error")
	p.Reset()
	p.WriteString(": ")
	p.WriteString(err.Error())
	p.WriteString("\n")
	p.Flush()
	return false
}

func update(ctx context.Context, p *printer.Printer, timeout time.Duration, version string) error {
	cfg := client.ClientConfig{Timeout: timeout, UserAgent: "fetch/" + version}
	c := client.NewClient(cfg)

	writeInfo(p, "fetching latest release tag")
	latest, err := getLatestRelease(ctx, c)
	if err != nil {
		return fmt.Errorf("fetching latest release: %w", err)
	}

	if strings.TrimPrefix(latest.TagName, "v") == version {
		p.WriteString("\n  currently using the latest version (v")
		p.WriteString(version)
		p.WriteString(")\n")
		p.Flush()
		return nil
	}

	artifactURL := getArtifactURL(latest)
	if artifactURL == "" {
		return fmt.Errorf("no %s/%s artifact found for %s",
			runtime.GOOS, runtime.GOARCH, latest.TagName)
	}

	writeInfo(p, fmt.Sprintf("downloading latest version (%s)", latest.TagName))
	rc, err := getArtifactReader(ctx, c, artifactURL)
	if err != nil {
		return fmt.Errorf("fetching artifact: %w", err)
	}
	defer rc.Close()

	tempDir, err := os.MkdirTemp("", "fetch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	err = unpackArtifact(tempDir, rc)
	if err != nil {
		return err
	}

	exePath, err := getExecutablePath()
	if err != nil {
		return err
	}
	src := filepath.Join(tempDir, getFetchFilename())
	err = selfReplace(exePath, src)
	if err != nil {
		return err
	}

	p.WriteString("\n  fetch successfully updated (v")
	p.WriteString(version)
	p.WriteString(" -> ")
	p.WriteString(latest.TagName)
	p.WriteString(")\n")
	p.Flush()
	return nil
}

type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

func getLatestRelease(ctx context.Context, c *client.Client) (*Release, error) {
	urlStr := getUpdateURL() + "/repos/ryanfowler/fetch/releases/latest"
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
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received status: %d", resp.StatusCode)
	}

	var release Release
	err = json.NewDecoder(resp.Body).Decode(&release)
	if err != nil {
		return nil, err
	}
	if release.TagName == "" {
		return nil, errors.New("no tag found")
	}

	return &release, nil
}

func getArtifactReader(ctx context.Context, c *client.Client, urlStr string) (io.ReadCloser, error) {
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

func getArtifactURL(release *Release) string {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	name := fmt.Sprintf("fetch-%s-%s-%s.%s",
		release.TagName, runtime.GOOS, runtime.GOARCH, ext)

	for _, asset := range release.Assets {
		if asset.Name == name {
			return asset.URL
		}
	}
	return ""
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
	p.WriteString("info")
	p.Reset()
	p.WriteString(": ")

	p.WriteString(s)
	p.WriteString("\n")
	p.Flush()
}

func randomString(n int) string {
	var sb strings.Builder
	sb.Grow(n)

	const letters = "abcdefghijklmnopqrstuvwxyz"
	for range n {
		b := letters[rand.IntN(len(letters))]
		sb.WriteByte(b)
	}

	return sb.String()
}

func getUpdateURL() string {
	if env := os.Getenv("FETCH_INTERNAL_UPDATE_URL"); env != "" {
		return env
	}
	return "https://api.github.com"
}
