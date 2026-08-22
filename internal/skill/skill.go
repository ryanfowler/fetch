// Package skill implements the offline Agent Skill workflow.
package skill

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ryanfowler/fetch/internal/fileutil"
)

const (
	SkillVersion = "1"
	metadataName = ".fetch-skill.json"
	lockName     = ".fetch-skill.lock"
)

// File is one file in the portable skill bundle. Path uses forward slashes.
type File struct {
	Path string
	Data []byte
}

// Bundle is the embedded, read-only skill payload.
type Bundle struct {
	FetchVersion string
	Files        []File
}

// NewBundle validates and copies embedded files. It also validates the
// evaluation fixture so a broken skill cannot be built into a release.
func NewBundle(fetchVersion string, files []File) (Bundle, error) {
	if fetchVersion == "" {
		fetchVersion = "v(dev)"
	}
	seen := make(map[string]struct{}, len(files))
	copyFiles := make([]File, 0, len(files))
	for _, file := range files {
		path, err := cleanRelativePath(file.Path)
		if err != nil {
			return Bundle{}, err
		}
		if _, ok := seen[path]; ok {
			return Bundle{}, fmt.Errorf("duplicate skill file %q", path)
		}
		seen[path] = struct{}{}
		copyFiles = append(copyFiles, File{Path: path, Data: append([]byte(nil), file.Data...)})
	}
	if len(copyFiles) == 0 {
		return Bundle{}, errors.New("embedded skill is empty")
	}
	if data, ok := fileData(copyFiles, "evals/evals.json"); ok {
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			return Bundle{}, fmt.Errorf("invalid embedded skill evaluation fixture: %w", err)
		}
	}
	if _, ok := fileData(copyFiles, "SKILL.md"); !ok {
		return Bundle{}, errors.New("embedded skill does not contain SKILL.md")
	}
	sort.Slice(copyFiles, func(i, j int) bool { return copyFiles[i].Path < copyFiles[j].Path })
	return Bundle{FetchVersion: fetchVersion, Files: copyFiles}, nil
}

func fileData(files []File, path string) ([]byte, bool) {
	for _, file := range files {
		if file.Path == path {
			return file.Data, true
		}
	}
	return nil, false
}

func cleanRelativePath(path string) (string, error) {
	path = filepath.ToSlash(path)
	if path == "" || path == "." || filepath.IsAbs(path) || strings.HasPrefix(path, "../") || path == ".." || strings.Contains(path, "\\") {
		return "", fmt.Errorf("invalid embedded skill path %q", path)
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean != path || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("invalid embedded skill path %q", path)
	}
	return clean, nil
}

// Options controls one skill action. Writers and paths are injectable to keep
// the filesystem workflow deterministic in tests.
type Options struct {
	Print          bool
	InstallAgent   string
	UninstallAgent string
	Scope          string
	Force          bool
	DryRun         bool

	HomeDir     string
	ProjectDir  string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Interactive bool
}

// Execute runs exactly one skill action and returns its process status.
func Execute(ctx context.Context, options Options, bundle Bundle) (int, error) {
	if err := validateOptions(options); err != nil {
		return 1, err
	}
	if options.Stdout == nil {
		options.Stdout = os.Stdout
	}
	if options.Stderr == nil {
		options.Stderr = os.Stderr
	}
	if options.Stdin == nil {
		options.Stdin = os.Stdin
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if options.Print {
		data, ok := fileData(bundle.Files, "SKILL.md")
		if !ok {
			return 1, errors.New("embedded skill does not contain SKILL.md")
		}
		if _, err := options.Stdout.Write(data); err != nil {
			return 1, err
		}
		return 0, nil
	}

	scope := options.Scope
	if scope == "" {
		scope = "user"
	}
	root, err := scopeRoot(scope, options)
	if err != nil {
		return 1, err
	}
	agent := options.InstallAgent
	if agent == "" {
		agent = options.UninstallAgent
	}
	destinations, err := destinations(root, scope, agent)
	if err != nil {
		return 1, err
	}
	install := options.InstallAgent != ""

	if install {
		return installSkill(ctx, options, bundle, destinations, root)
	}
	return uninstallSkill(ctx, options, bundle, destinations, root)
}

func validateOptions(o Options) error {
	actions := 0
	if o.Print {
		actions++
	}
	if o.InstallAgent != "" {
		actions++
	}
	if o.UninstallAgent != "" {
		actions++
	}
	if actions != 1 {
		return errors.New("exactly one skill action must be specified")
	}
	if o.Print && (o.Scope != "" || o.Force || o.DryRun) {
		return errors.New("scope, force, and dry-run require a skill installation or removal")
	}
	if o.InstallAgent != "" && o.UninstallAgent != "" {
		return errors.New("install and uninstall cannot be combined")
	}
	return nil
}

func scopeRoot(scope string, o Options) (string, error) {
	var root string
	switch scope {
	case "user":
		root = o.HomeDir
		if root == "" {
			root, _ = os.UserHomeDir()
		}
		if root == "" {
			return "", errors.New("unable to determine the user home directory")
		}
	case "project":
		root = o.ProjectDir
		if root == "" {
			root, _ = os.Getwd()
		}
		if root == "" {
			return "", errors.New("unable to determine the project directory")
		}
	default:
		return "", fmt.Errorf("invalid scope %q: must be one of [user, project]", scope)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve skill scope: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func destinations(root, scope, agent string) ([]string, error) {
	base := func(relative string) string { return filepath.Join(root, relative, "fetch") }
	var result []string
	switch agent {
	case "", "auto", "agents":
		result = []string{base(filepath.Join(".agents", "skills"))}
	case "codex":
		result = []string{base(filepath.Join(".codex", "skills"))}
	case "claude":
		result = []string{base(filepath.Join(".claude", "skills"))}
	case "gemini":
		result = []string{base(filepath.Join(".gemini", "skills"))}
	case "pi":
		relative := filepath.Join(".pi", "skills")
		if scope == "user" {
			relative = filepath.Join(".pi", "agent", "skills")
		}
		result = []string{base(relative)}
	case "all":
		result = []string{
			base(filepath.Join(".agents", "skills")),
			base(filepath.Join(".codex", "skills")),
			base(filepath.Join(".claude", "skills")),
			base(filepath.Join(".gemini", "skills")),
		}
		piRelative := filepath.Join(".pi", "skills")
		if scope == "user" {
			piRelative = filepath.Join(".pi", "agent", "skills")
		}
		result = append(result, base(piRelative))
	default:
		return nil, fmt.Errorf("invalid skill agent %q: must be one of [auto, agents, codex, claude, gemini, pi, all]", agent)
	}
	return result, nil
}

type installationState uint8

const (
	stateMissing installationState = iota
	stateCurrent
	stateOutdated
	stateModified
)

type fileRecord struct {
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type installationMetadata struct {
	SkillVersion string                `json:"skill_version"`
	FetchVersion string                `json:"fetch_version"`
	Files        map[string]fileRecord `json:"files"`
}

func (b Bundle) manifest() installationMetadata {
	files := make(map[string]fileRecord, len(b.Files))
	for _, file := range b.Files {
		hash := sha256.Sum256(file.Data)
		files[file.Path] = fileRecord{SHA256: hex.EncodeToString(hash[:]), Size: len(file.Data)}
	}
	return installationMetadata{SkillVersion: SkillVersion, FetchVersion: b.FetchVersion, Files: files}
}

func installSkill(ctx context.Context, o Options, b Bundle, destinations []string, root string) (int, error) {
	if err := printDestinations(o.Stderr, "Skill installation destinations:", destinations); err != nil {
		return 1, err
	}
	if err := validateDestinations(destinations, root, true, b, o.Force); err != nil {
		return 1, err
	}
	if o.DryRun {
		_, _ = io.WriteString(o.Stderr, "Dry run: no files were written.\n")
		return 0, nil
	}
	if o.Interactive {
		ok, err := confirm(ctx, o.Stdin, o.Stderr, "Install the bundled fetch skill? [y/N] ")
		if err != nil {
			return 1, err
		}
		if !ok {
			_, _ = io.WriteString(o.Stderr, "Installation cancelled.\n")
			return 0, nil
		}
	}
	locks, err := acquireLocks(ctx, destinations, true)
	if err != nil {
		return 1, err
	}
	defer releaseLocks(locks)
	if err := validateDestinations(destinations, root, true, b, o.Force); err != nil {
		return 1, err
	}
	for _, destination := range destinations {
		if err := installDirectory(destination, b, o.Force, root); err != nil {
			return 1, err
		}
	}
	_, _ = fmt.Fprintf(o.Stderr, "Installed fetch skill %s (fetch %s).\n", SkillVersion, b.FetchVersion)
	return 0, nil
}

func uninstallSkill(ctx context.Context, o Options, b Bundle, destinations []string, root string) (int, error) {
	if err := printDestinations(o.Stderr, "Skill uninstall destinations:", destinations); err != nil {
		return 1, err
	}
	if err := validateDestinations(destinations, root, false, b, o.Force); err != nil {
		return 1, err
	}
	if o.DryRun {
		_, _ = io.WriteString(o.Stderr, "Dry run: no files were removed.\n")
		return 0, nil
	}
	missing, err := allMissing(destinations)
	if err != nil {
		return 1, err
	}
	if missing {
		_, _ = io.WriteString(o.Stderr, "Fetch skill is not installed; nothing to remove.\n")
		return 0, nil
	}
	if o.Interactive {
		ok, err := confirm(ctx, o.Stdin, o.Stderr, "Uninstall the fetch skill? [y/N] ")
		if err != nil {
			return 1, err
		}
		if !ok {
			_, _ = io.WriteString(o.Stderr, "Uninstall cancelled.\n")
			return 0, nil
		}
	}
	locks, err := acquireLocks(ctx, destinations, false)
	if err != nil {
		return 1, err
	}
	defer releaseLocks(locks)
	if err := validateDestinations(destinations, root, false, b, o.Force); err != nil {
		return 1, err
	}
	for _, destination := range destinations {
		if err := validateDestinations([]string{destination}, root, false, b, o.Force); err != nil {
			return 1, err
		}
		if err := removeManaged(destination); err != nil {
			return 1, err
		}
	}
	_, _ = io.WriteString(o.Stderr, "Uninstalled fetch skill.\n")
	return 0, nil
}

func printDestinations(w io.Writer, title string, destinations []string) error {
	if _, err := io.WriteString(w, title+"\n"); err != nil {
		return err
	}
	for _, destination := range destinations {
		if _, err := fmt.Fprintf(w, "  %s\n", destination); err != nil {
			return err
		}
	}
	return nil
}

func validateDestinations(destinations []string, root string, forInstall bool, b Bundle, force bool) error {
	for _, destination := range destinations {
		if err := validatePathComponents(root, destination); err != nil {
			return err
		}
		state, err := stateOf(destination, b)
		if err != nil {
			return fmt.Errorf("inspect skill installation %q: %w", destination, err)
		}
		if state == stateModified && !force {
			action := "overwrite"
			if !forInstall {
				action = "remove"
			}
			return fmt.Errorf("refusing to %s modified skill installation %q; use --force", action, destination)
		}
	}
	return nil
}

// validatePathComponents rejects symlinks in the destination's existing
// parent chain. The scope root itself is intentionally allowed to be a
// symlink, because home directories commonly are.
func validatePathComponents(root, destination string) error {
	root = filepath.Clean(root)
	clean := filepath.Clean(destination)
	if !filepath.IsAbs(root) || !filepath.IsAbs(clean) {
		return fmt.Errorf("skill destination must be absolute: %q", destination)
	}
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("skill destination escapes its scope: %q", destination)
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect skill destination component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked skill destination component %q", current)
		}
		if !info.IsDir() && current != clean {
			return fmt.Errorf("skill destination component %q is not a directory", current)
		}
	}
	return nil
}

func allMissing(destinations []string) (bool, error) {
	for _, destination := range destinations {
		info, err := os.Lstat(destination)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return false, fmt.Errorf("refusing symlinked skill destination %q", destination)
			}
			return false, nil
		}
		if !os.IsNotExist(err) {
			return false, err
		}
	}
	return true, nil
}

func stateOf(path string, b Bundle) (installationState, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return stateMissing, nil
	}
	if err != nil {
		return stateModified, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return stateModified, nil
	}
	metadataPath := filepath.Join(path, metadataName)
	metadataInfo, err := os.Lstat(metadataPath)
	if err != nil || !metadataInfo.Mode().IsRegular() || !privateFileMode(metadataInfo) {
		return stateModified, nil
	}
	metadata, metadataOK := readMetadata(metadataPath)
	if !metadataOK || !validMetadata(metadata, b) {
		return stateModified, nil
	}
	actual, err := installedFiles(path)
	if err != nil {
		return stateModified, err
	}
	if hasUnexpectedDirectories(path, metadata.Files) {
		return stateModified, nil
	}
	if !sameKeys(actual, metadata.Files) {
		return stateModified, nil
	}
	for relative, record := range metadata.Files {
		filePath := filepath.Join(path, filepath.FromSlash(relative))
		fileInfo, err := os.Lstat(filePath)
		if err != nil || !fileInfo.Mode().IsRegular() || !privateFileMode(fileInfo) {
			return stateModified, nil
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return stateModified, nil
		}
		if len(data) != record.Size || hashBytes(data) != record.SHA256 {
			return stateModified, nil
		}
	}
	// The embedded manifest is the trust anchor. A changed file, changed
	// metadata, or an installation from another bundle requires --force.
	expected := b.manifest()
	if metadata.SkillVersion != expected.SkillVersion || metadata.FetchVersion != expected.FetchVersion || !sameManifest(metadata.Files, expected.Files) {
		return stateModified, nil
	}
	return stateCurrent, nil
}

func readMetadata(path string) (installationMetadata, bool) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		return installationMetadata{}, false
	}
	var metadata installationMetadata
	if json.Unmarshal(data, &metadata) != nil || metadata.SkillVersion == "" || metadata.Files == nil {
		return installationMetadata{}, false
	}
	return metadata, true
}

func validMetadata(metadata installationMetadata, bundle Bundle) bool {
	if len(metadata.Files) == 0 || (len(bundle.Files) > 0 && len(metadata.Files) != len(bundle.Files)) {
		return false
	}
	if len(bundle.Files) > 0 {
		expected := bundle.manifest().Files
		for path := range expected {
			if _, ok := metadata.Files[path]; !ok {
				return false
			}
		}
	}
	for path, record := range metadata.Files {
		if _, err := cleanRelativePath(path); err != nil || record.Size < 0 || len(record.SHA256) != sha256.Size*2 {
			return false
		}
		if _, err := hex.DecodeString(record.SHA256); err != nil {
			return false
		}
	}
	return true
}

func installedFiles(root string) (map[string]struct{}, error) {
	files := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("skill installation contains symlink %q", rel)
		}
		if rel == metadataName {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("skill installation contains non-regular file %q", rel)
		}
		files[rel] = struct{}{}
		return nil
	})
	return files, err
}

func hasUnexpectedDirectories(root string, expected map[string]fileRecord) bool {
	allowed := map[string]struct{}{}
	for path := range expected {
		dir := filepath.ToSlash(filepath.Dir(filepath.FromSlash(path)))
		for dir != "." && dir != "" {
			allowed[dir] = struct{}{}
			dir = filepath.ToSlash(filepath.Dir(filepath.FromSlash(dir)))
		}
	}
	unexpected := false
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || path == root || !entry.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if _, ok := allowed[filepath.ToSlash(rel)]; !ok {
			unexpected = true
			return filepath.SkipDir
		}
		return nil
	})
	return unexpected
}

func sameKeys(actual map[string]struct{}, expected map[string]fileRecord) bool {
	if len(actual) != len(expected) {
		return false
	}
	for path := range expected {
		if _, ok := actual[path]; !ok {
			return false
		}
	}
	return true
}

func sameManifest(a, b map[string]fileRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for path, left := range a {
		if right, ok := b[path]; !ok || left != right {
			return false
		}
	}
	return true
}

func privateFileMode(info os.FileInfo) bool {
	if runtime.GOOS == "windows" {
		// Windows does not expose Unix owner permission bits. Ensure files are
		// non-executable; ACL privacy is provided by the parent directory and
		// the platform security model.
		return info.Mode().Perm()&0111 == 0
	}
	return info.Mode().Perm() == 0600
}

func hashBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func installDirectory(path string, b Bundle, force bool, root string) error {
	state, err := stateOf(path, b)
	if err != nil {
		return err
	}
	if state == stateModified && !force {
		return fmt.Errorf("refusing to overwrite modified skill installation %q; use --force", path)
	}
	if state == stateMissing {
		parent := filepath.Dir(path)
		if err := ensureDirectory(parent); err != nil {
			return err
		}
		stage, err := createStage(parent)
		if err != nil {
			return err
		}
		if err := writeBundle(stage, b); err != nil {
			_ = os.RemoveAll(stage)
			return err
		}
		if err := validatePathComponents(root, path); err != nil {
			_ = os.RemoveAll(stage)
			return err
		}
		if err := os.Rename(stage, path); err != nil {
			_ = os.RemoveAll(stage)
			return fmt.Errorf("install skill %q: %w", path, err)
		}
		return nil
	}
	if force || state == stateOutdated {
		return replaceDirectory(path, b, root)
	}
	return writeBundle(path, b)
}

func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("skill parent %q is not a directory", path)
	}
	return nil
}

func createStage(parent string) (string, error) {
	if err := ensureDirectory(parent); err != nil {
		return "", err
	}
	for i := 0; i < 20; i++ {
		name := filepath.Join(parent, fmt.Sprintf(".fetch-skill-stage-%d-%d", os.Getpid(), time.Now().UnixNano()+int64(i)))
		if err := os.Mkdir(name, 0700); err == nil {
			return name, nil
		} else if !os.IsExist(err) {
			return "", err
		}
	}
	return "", errors.New("unable to create a unique skill staging directory")
}

func replaceDirectory(path string, b Bundle, root string) error {
	parent := filepath.Dir(path)
	if err := ensureDirectory(parent); err != nil {
		return err
	}
	stage, err := createStage(parent)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := writeBundle(stage, b); err != nil {
		return err
	}
	snapshot, err := snapshotFiles(path)
	if err != nil {
		return err
	}
	rollback := func(original error) error {
		if restoreErr := restoreSnapshot(path, snapshot); restoreErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", original, restoreErr)
		}
		return original
	}
	// Keep the existing directory in place. Each file is committed atomically
	// and the manifest is written last, so a failed replacement never exposes
	// an absent installation or a partially written file.
	if err := validatePathComponents(root, path); err != nil {
		return err
	}
	for _, file := range b.Files {
		data, err := os.ReadFile(filepath.Join(stage, filepath.FromSlash(file.Path)))
		if err != nil {
			return rollback(err)
		}
		if err := atomicWrite(filepath.Join(path, filepath.FromSlash(file.Path)), data); err != nil {
			return rollback(err)
		}
	}
	metadata, err := os.ReadFile(filepath.Join(stage, metadataName))
	if err != nil {
		return rollback(err)
	}
	if err := atomicWrite(filepath.Join(path, metadataName), metadata); err != nil {
		return rollback(err)
	}
	if err := removeUnknownFiles(path, b); err != nil {
		return rollback(err)
	}
	return nil
}

type snapshotFile struct {
	data []byte
	mode os.FileMode
}

func snapshotFiles(root string) (map[string]snapshotFile, error) {
	files := make(map[string]snapshotFile)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("skill installation contains symlink %q", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("skill installation contains non-regular file %q", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = snapshotFile{data: data, mode: info.Mode().Perm()}
		return nil
	})
	return files, err
}

func restoreSnapshot(root string, files map[string]snapshotFile) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		file := files[path]
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := atomicWrite(full, file.data); err != nil {
			return err
		}
		if err := os.Chmod(full, file.mode); err != nil {
			return err
		}
	}
	return nil
}

func removeUnknownFiles(root string, b Bundle) error {
	expected := make(map[string]struct{}, len(b.Files))
	allowedDirs := make(map[string]struct{})
	for _, file := range b.Files {
		expected[file.Path] = struct{}{}
		dir := filepath.ToSlash(filepath.Dir(filepath.FromSlash(file.Path)))
		for dir != "." && dir != "" {
			allowedDirs[dir] = struct{}{}
			dir = filepath.ToSlash(filepath.Dir(filepath.FromSlash(dir)))
		}
	}
	var remove []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == metadataName {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			remove = append(remove, path)
			return nil
		}
		if entry.IsDir() {
			if _, ok := allowedDirs[rel]; !ok {
				remove = append(remove, path)
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := expected[rel]; !ok {
			remove = append(remove, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(remove, func(i, j int) bool { return len(remove[i]) > len(remove[j]) })
	for _, path := range remove {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func writeBundle(root string, b Bundle) error {
	for _, file := range b.Files {
		if err := atomicWrite(filepath.Join(root, filepath.FromSlash(file.Path)), file.Data); err != nil {
			return err
		}
	}
	data, err := json.Marshal(b.manifest(), json.Deterministic(true))
	if err != nil {
		return err
	}
	formatted := jsontext.Value(data)
	if err := formatted.Indent(jsontext.WithIndent("  ")); err != nil {
		return err
	}
	data = formatted
	data = append(data, '\n')
	return atomicWrite(filepath.Join(root, metadataName), data)
}

func atomicWrite(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := ensureDirectory(parent); err != nil {
		return err
	}
	var temp string
	for i := 0; i < 20; i++ {
		temp = filepath.Join(parent, fmt.Sprintf(".fetch-skill-file-%d-%d", os.Getpid(), time.Now().UnixNano()+int64(i)))
		file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return err
		}
		if _, err = file.Write(data); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Chmod(temp, 0600)
		}
		if err == nil {
			err = fileutil.AtomicReplaceFileNoSymlink(temp, path)
			if err == nil {
				_ = fileutil.SyncDir(parent)
				return nil
			}
		}
		_ = os.Remove(temp)
		return err
	}
	return errors.New("unable to create a unique skill temporary file")
}

func removeManaged(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove symlinked skill destination %q", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to remove non-directory skill destination %q", path)
	}
	return os.RemoveAll(path)
}

type operationLock struct{ path string }

func acquireLocks(ctx context.Context, destinations []string, includeMissing bool) ([]operationLock, error) {
	parents := make(map[string]struct{})
	for _, destination := range destinations {
		_, err := os.Lstat(destination)
		exists := err == nil
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if includeMissing || exists {
			parents[filepath.Dir(destination)] = struct{}{}
		}
	}
	parentList := make([]string, 0, len(parents))
	for parent := range parents {
		parentList = append(parentList, parent)
	}
	sort.Strings(parentList)
	locks := make([]operationLock, 0, len(parentList))
	for _, parent := range parentList {
		if err := ensureDirectory(parent); err != nil {
			releaseLocks(locks)
			return nil, err
		}
		path := filepath.Join(parent, lockName)
		lock, err := acquireLock(ctx, path)
		if err != nil {
			releaseLocks(locks)
			return nil, err
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

func acquireLock(ctx context.Context, path string) (operationLock, error) {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
			_ = file.Close()
			return operationLock{path: path}, nil
		}
		if !os.IsExist(err) && !os.IsPermission(err) {
			return operationLock{}, err
		}
		select {
		case <-ctx.Done():
			return operationLock{}, ctx.Err()
		case <-deadline.C:
			return operationLock{}, fmt.Errorf("timed out waiting for skill operation lock %q", path)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func releaseLocks(locks []operationLock) {
	for i := len(locks) - 1; i >= 0; i-- {
		_ = os.Remove(locks[i].path)
	}
}

func confirm(ctx context.Context, input io.Reader, output io.Writer, prompt string) (bool, error) {
	if _, err := io.WriteString(output, prompt); err != nil {
		return false, err
	}
	var answer string
	result := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(input).ReadString('\n')
		answer = line
		if err == io.EOF {
			err = nil
		}
		result <- err
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case err := <-result:
		if err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
