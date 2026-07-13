use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::Cli;
use crate::error::FetchError;
use crate::{core, fileutil};

const SKILL_VERSION: &str = "1";
const METADATA_FILE: &str = ".fetch-skill.json";

const FILES: &[(&str, &str)] = &[
    ("SKILL.md", include_str!("../skills/fetch/SKILL.md")),
    (
        "references/http.md",
        include_str!("../skills/fetch/references/http.md"),
    ),
    (
        "references/diagnostics.md",
        include_str!("../skills/fetch/references/diagnostics.md"),
    ),
    (
        "references/grpc.md",
        include_str!("../skills/fetch/references/grpc.md"),
    ),
    (
        "references/websocket.md",
        include_str!("../skills/fetch/references/websocket.md"),
    ),
    (
        "evals/evals.json",
        include_str!("../skills/fetch/evals/evals.json"),
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    User,
    Project,
}

#[derive(Debug)]
struct Destination {
    path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
struct InstallationMetadata {
    skill_version: String,
    fetch_version: String,
    files: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallationState {
    Missing,
    Current,
    Outdated,
    Modified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SkillAction {
    Print,
    Install,
    Uninstall,
}

impl SkillAction {
    fn flag(self) -> &'static str {
        match self {
            Self::Print => "--skill",
            Self::Install => "--install-skill",
            Self::Uninstall => "--uninstall-skill",
        }
    }

    fn mutates(self) -> bool {
        matches!(self, Self::Install | Self::Uninstall)
    }
}

pub fn is_action(cli: &Cli) -> bool {
    cli.skill || cli.install_skill.is_some() || cli.uninstall_skill.is_some()
}

pub fn execute(cli: &Cli) -> Result<i32, FetchError> {
    validate_cli(cli)?;
    if cli.skill {
        core::write_stdout(FILES[0].1)?;
        return Ok(0);
    }
    let scope = parse_scope(cli.scope.as_deref())?;
    if let Some(agent) = cli.install_skill.as_deref() {
        return install(scope, agent, cli.dry_run, cli.force);
    }
    if let Some(agent) = cli.uninstall_skill.as_deref() {
        return uninstall(scope, agent, cli.dry_run, cli.force);
    }
    unreachable!("skill action was checked by caller")
}

pub(crate) fn validate_cli(cli: &Cli) -> Result<(), FetchError> {
    let actions = [
        (cli.skill, SkillAction::Print),
        (cli.install_skill.is_some(), SkillAction::Install),
        (cli.uninstall_skill.is_some(), SkillAction::Uninstall),
    ];
    let selected: Vec<_> = actions
        .into_iter()
        .filter_map(|(selected, action)| selected.then_some(action))
        .collect();
    if selected.len() != 1 {
        return Err("exactly one skill action must be specified".into());
    }
    let action = selected[0];

    if cli.url.is_some() || !cli.extra_args.is_empty() {
        return Err("a URL or positional argument cannot be used with a skill action".into());
    }
    if cli.scope.is_some() && !action.mutates() {
        return Err(format!("flag '--scope' cannot be used with '{}'", action.flag()).into());
    }
    if cli.force && !action.mutates() {
        return Err(format!("flag '--force' cannot be used with '{}'", action.flag()).into());
    }
    if cli.dry_run && !action.mutates() {
        return Err(format!("flag '--dry-run' cannot be used with '{}'", action.flag()).into());
    }

    let top_level_options = [
        (cli.auto_update.is_some(), "--auto-update"),
        (cli.buildinfo, "--buildinfo"),
        (cli.color.is_some(), "--color"),
        (cli.complete.is_some(), "--complete"),
        (cli.config.is_some(), "--config"),
        (cli.from_curl.is_some(), "--from-curl"),
        (cli.help, "--help"),
        (cli.inspect_dns, "--inspect-dns"),
        (cli.inspect_tls, "--inspect-tls"),
        (cli.silent, "--silent"),
        (cli.update, "--update"),
        (cli.verbose > 0, "--verbose"),
        (cli.version, "--version"),
    ];
    if let Some((_, flag)) = top_level_options.into_iter().find(|(set, _)| *set) {
        return Err(incompatible_option(flag, action));
    }

    if let Some(flag) = crate::flag_registry::set_flag_names(cli).find(|flag| *flag != "--dry-run")
    {
        return Err(incompatible_option(flag, action));
    }
    Ok(())
}

fn incompatible_option(flag: &str, action: SkillAction) -> FetchError {
    format!("flag '{flag}' cannot be used with '{}'", action.flag()).into()
}

fn parse_scope(value: Option<&str>) -> Result<Scope, FetchError> {
    match value.unwrap_or("user") {
        "user" => Ok(Scope::User),
        "project" => Ok(Scope::Project),
        value => Err(FetchError::invalid_value(
            "--scope",
            value,
            "must be one of [user, project]",
        )),
    }
}

fn destinations(scope: Scope, agent: &str) -> Result<Vec<Destination>, FetchError> {
    let root = match scope {
        Scope::User => home_dir()?,
        Scope::Project => std::env::current_dir()?,
    };
    let destination = |relative: &str| Destination {
        path: root.join(relative).join("fetch"),
    };
    let agents = || destination(".agents/skills");
    let codex = || destination(".codex/skills");
    let claude = || destination(".claude/skills");
    let gemini = || destination(".gemini/skills");
    let pi = || {
        destination(match scope {
            Scope::User => ".pi/agent/skills",
            Scope::Project => ".pi/skills",
        })
    };

    let result = match agent {
        "auto" | "agents" => vec![agents()],
        "codex" => vec![codex()],
        "claude" => vec![claude()],
        "gemini" => vec![gemini()],
        "pi" => vec![pi()],
        "all" => vec![agents(), codex(), claude(), gemini(), pi()],
        value => {
            return Err(FetchError::invalid_value(
                "--install-skill",
                value,
                "must be one of [agents, codex, claude, gemini, pi, all]",
            ));
        }
    };
    Ok(result)
}

fn home_dir() -> Result<PathBuf, FetchError> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| "unable to determine the user home directory".into())
}

fn install(scope: Scope, agent: &str, dry_run: bool, force: bool) -> Result<i32, FetchError> {
    let destinations = destinations(scope, agent)?;
    write_stderr("Skill installation destinations:\n")?;
    for destination in &destinations {
        write_stderr(format!("  {}\n", destination.path.display()))?;
    }

    validate_install_destinations(&destinations, force)?;
    if dry_run {
        write_stderr("Dry run: no files were written.\n")?;
        return Ok(0);
    }
    if core::stdio().stdin_is_terminal() && !confirm("Install the bundled fetch skill? [y/N] ")? {
        write_stderr("Installation cancelled.\n")?;
        return Ok(0);
    }

    let _locks = acquire_operation_locks(&destinations, true)?;
    // The installation may have changed while confirmation was pending or
    // while another fetch process held an operation lock.
    validate_install_destinations(&destinations, force)?;
    for destination in &destinations {
        install_directory(&destination.path, force)?;
    }
    write_stderr(format!(
        "Installed fetch skill {} (fetch {}).\n",
        SKILL_VERSION,
        core::version()
    ))?;
    Ok(0)
}

fn uninstall(scope: Scope, agent: &str, dry_run: bool, force: bool) -> Result<i32, FetchError> {
    let destinations = destinations(scope, agent)?;
    write_stderr("Skill uninstall destinations:\n")?;
    for destination in &destinations {
        write_stderr(format!("  {}\n", destination.path.display()))?;
        ensure_removable(&destination.path, force)?;
    }
    if dry_run {
        write_stderr("Dry run: no files were removed.\n")?;
        return Ok(0);
    }
    if destinations_are_missing(&destinations)? {
        write_stderr("Fetch skill is not installed; nothing to remove.\n")?;
        return Ok(0);
    }
    if core::stdio().stdin_is_terminal() && !confirm("Uninstall the fetch skill? [y/N] ")? {
        write_stderr("Uninstall cancelled.\n")?;
        return Ok(0);
    }
    let _locks = acquire_operation_locks(&destinations, false)?;
    // Revalidate every destination after confirmation while serialized with
    // other fetch skill operations. This preflight avoids a known modified
    // destination causing a partially completed uninstall.
    for destination in &destinations {
        ensure_removable(&destination.path, force)?;
    }

    // Recheck immediately before each deletion as defense against
    // non-cooperating processes and edits.
    for destination in destinations {
        ensure_removable(&destination.path, force)?;
        remove_path(&destination.path)?;
    }
    write_stderr("Uninstalled fetch skill.\n")?;
    Ok(0)
}

fn destinations_are_missing(destinations: &[Destination]) -> Result<bool, FetchError> {
    for destination in destinations {
        match fs::symlink_metadata(&destination.path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

fn validate_install_destinations(
    destinations: &[Destination],
    force: bool,
) -> Result<(), FetchError> {
    for destination in destinations {
        ensure_writable_installation(&destination.path, force)?;
    }
    Ok(())
}

fn acquire_operation_locks(
    destinations: &[Destination],
    include_missing: bool,
) -> Result<Vec<fileutil::FileLock>, FetchError> {
    let mut parents = BTreeSet::new();
    for destination in destinations {
        let exists = match fs::symlink_metadata(&destination.path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if include_missing || exists {
            parents.insert(
                destination
                    .path
                    .parent()
                    .ok_or("invalid skill destination")?
                    .to_path_buf(),
            );
        }
    }

    let mut locks = Vec::with_capacity(parents.len());
    for parent in parents {
        fs::create_dir_all(&parent)?;
        let lock_path = parent.join(".fetch-skill.lock");
        locks.push(fileutil::FileLock::acquire_with_timeout(
            lock_path,
            Duration::from_secs(5),
            || {
                let _ = write_stderr("Waiting for another fetch skill operation...\n");
            },
            |timeout| {
                FetchError::Message(format!(
                    "timed out waiting {:.0}s for another fetch skill operation",
                    timeout.as_secs_f64()
                ))
            },
        )?);
    }
    Ok(locks)
}

fn write_stderr(message: impl AsRef<str>) -> io::Result<()> {
    let mut printer = core::Printer::stderr(None);
    printer.push_str(message.as_ref());
    printer.flush_to(&mut io::stderr())
}

fn confirm(prompt: &str) -> io::Result<bool> {
    write_stderr(prompt)?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn ensure_writable_installation(path: &Path, force: bool) -> Result<(), FetchError> {
    if installation_state(path)? == InstallationState::Modified && !force {
        return Err(format!(
            "refusing to overwrite modified skill installation '{}'; use --force",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn ensure_removable(path: &Path, force: bool) -> Result<(), FetchError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_symlink()
        && installation_state(path)? == InstallationState::Modified
        && !force
    {
        return Err(format!(
            "refusing to remove modified skill installation '{}'; use --force",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn install_directory(path: &Path, force: bool) -> Result<(), FetchError> {
    let state = installation_state(path)?;
    ensure_writable_installation(path, force)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        // Older fetch versions could create a managed Claude symlink. Migrate
        // an unmodified symlink to a direct agent-specific copy without
        // requiring --force; modified or unrelated paths remain protected.
        let safe_managed_symlink =
            metadata.file_type().is_symlink() && state != InstallationState::Modified;
        if !force && !safe_managed_symlink {
            return Err(format!("'{}' is not an installation directory", path.display()).into());
        }
        remove_path(path)?;
    }

    if !path.exists() {
        install_fresh_directory(path)?;
    } else if force || state == InstallationState::Outdated {
        replace_directory(path)?;
    } else {
        write_installation_files(path)?;
    }
    Ok(())
}

fn install_fresh_directory(path: &Path) -> Result<(), FetchError> {
    let parent = path.parent().ok_or("invalid skill destination")?;
    fs::create_dir_all(parent)?;
    let stage = temporary_path(parent, ".fetch-skill-stage");
    fs::create_dir(&stage)?;
    if let Err(error) = write_installation_files(&stage) {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }
    fileutil::atomic_replace_file(&stage, path)?;
    Ok(())
}

fn replace_directory(path: &Path) -> Result<(), FetchError> {
    let parent = path.parent().ok_or("invalid skill destination")?;
    let stage = temporary_path(parent, ".fetch-skill-stage");
    fs::create_dir(&stage)?;
    if let Err(error) = write_installation_files(&stage) {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }

    let backup = temporary_path(parent, ".fetch-skill-backup");
    fs::rename(path, &backup)?;
    if let Err(error) = fileutil::atomic_replace_file(&stage, path) {
        let _ = fs::rename(&backup, path);
        let _ = fs::remove_dir_all(&stage);
        return Err(error.into());
    }
    fs::remove_dir_all(backup)?;
    Ok(())
}

fn write_installation_files(path: &Path) -> Result<(), FetchError> {
    for (relative, contents) in FILES {
        atomic_write(path.join(relative), contents.as_bytes())?;
    }
    let metadata = InstallationMetadata {
        skill_version: SKILL_VERSION.to_string(),
        fetch_version: core::version().to_string(),
        files: bundled_hashes(),
    };
    let mut bytes = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| FetchError::Message(error.to_string()))?;
    bytes.push(b'\n');
    atomic_write(path.join(METADATA_FILE), &bytes)?;
    Ok(())
}

fn atomic_write(path: PathBuf, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = temporary_path(parent, ".fetch-skill-file");
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let result = if path.exists() {
        fileutil::atomic_replace_file(&temp, &path)
    } else {
        fileutil::atomic_write_new_file(&temp, &path)
    };
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn temporary_path(parent: &Path, prefix: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!("{prefix}-{}-{nonce}", std::process::id()))
}

fn remove_path(path: &Path) -> io::Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    }
}

fn bundled_hashes() -> BTreeMap<String, String> {
    FILES
        .iter()
        .map(|(path, contents)| ((*path).to_string(), hash(contents.as_bytes())))
        .collect()
}

fn installation_state(path: &Path) -> Result<InstallationState, FetchError> {
    let Ok(path_metadata) = fs::symlink_metadata(path) else {
        return Ok(InstallationState::Missing);
    };
    if path_metadata.file_type().is_symlink() {
        let Ok(target) = fs::canonicalize(path) else {
            return Ok(InstallationState::Modified);
        };
        return installation_state(&target);
    }
    if !path_metadata.is_dir() {
        return Ok(InstallationState::Modified);
    }

    let expected = bundled_hashes();
    let metadata_path = path.join(METADATA_FILE);
    let recorded = fs::read(&metadata_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<InstallationMetadata>(&bytes).ok());
    let expected_files = recorded
        .as_ref()
        .map(|metadata| &metadata.files)
        .unwrap_or(&expected);
    let actual_paths = installed_relative_files(path)?;
    let expected_paths: BTreeSet<_> = expected_files.keys().cloned().collect();
    if actual_paths != expected_paths {
        return Ok(InstallationState::Modified);
    }
    for (relative, expected_hash) in expected_files {
        let bytes = fs::read(path.join(relative))?;
        if hash(&bytes) != *expected_hash {
            return Ok(InstallationState::Modified);
        }
    }
    let Some(recorded) = recorded else {
        return Ok(if expected_files == &expected {
            InstallationState::Current
        } else {
            InstallationState::Outdated
        });
    };
    if recorded.skill_version == SKILL_VERSION && recorded.files == expected {
        Ok(InstallationState::Current)
    } else {
        Ok(InstallationState::Outdated)
    }
}

fn installed_relative_files(root: &Path) -> io::Result<BTreeSet<String>> {
    fn visit(root: &Path, dir: &Path, result: &mut BTreeSet<String>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                visit(root, &path, result)?;
            } else if path.file_name().and_then(|name| name.to_str()) != Some(METADATA_FILE) {
                let relative = path.strip_prefix(root).expect("walk remains below root");
                result.insert(relative.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
    let mut result = BTreeSet::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

fn hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn skill_actions_reject_ignored_options() {
        for args in [
            vec!["fetch", "--skill", "--update"],
            vec!["fetch", "--skill", "--scope", "project"],
            vec!["fetch", "--skill", "--header", "x-test: true"],
            vec!["fetch", "--install-skill", "--method", "POST"],
            vec!["fetch", "--uninstall-skill", "--complete", "bash"],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            let error = validate_cli(&cli).unwrap_err().to_string();
            assert!(
                error.contains("cannot be used"),
                "unexpected validation for {args:?}: {error}"
            );
        }
    }

    #[test]
    fn skill_actions_accept_only_their_applicable_modifiers() {
        for args in [
            vec!["fetch", "--skill"],
            vec![
                "fetch",
                "--install-skill",
                "pi",
                "--scope",
                "project",
                "--dry-run",
                "--force",
            ],
            vec![
                "fetch",
                "--uninstall-skill",
                "all",
                "--scope",
                "user",
                "--dry-run",
                "--force",
            ],
        ] {
            let cli = Cli::try_parse_from(&args).unwrap();
            validate_cli(&cli)
                .unwrap_or_else(|error| panic!("unexpected validation for {args:?}: {error}"));
        }
    }

    #[test]
    fn installation_detects_local_modifications() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fetch");
        install_directory(&path, false).unwrap();
        assert_eq!(
            installation_state(&path).unwrap(),
            InstallationState::Current
        );

        fs::write(path.join("SKILL.md"), "changed").unwrap();
        assert_eq!(
            installation_state(&path).unwrap(),
            InstallationState::Modified
        );
        assert!(install_directory(&path, false).is_err());
        install_directory(&path, true).unwrap();
        assert_eq!(
            installation_state(&path).unwrap(),
            InstallationState::Current
        );
    }

    #[test]
    fn installation_records_versions_and_every_bundled_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fetch");
        install_directory(&path, false).unwrap();
        let metadata: InstallationMetadata =
            serde_json::from_slice(&fs::read(path.join(METADATA_FILE)).unwrap()).unwrap();
        assert_eq!(metadata.skill_version, SKILL_VERSION);
        assert_eq!(metadata.fetch_version, core::version());
        assert_eq!(metadata.files, bundled_hashes());
    }
}
