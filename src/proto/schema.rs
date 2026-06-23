use prost_reflect::{DescriptorPool, MessageDescriptor, MethodDescriptor, ServiceDescriptor};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::FetchError;
use crate::proto::ProtoError;
use crate::proto::descriptor_wire::reflected_file_name;

#[derive(Debug, Clone)]
pub struct Schema {
    pool: DescriptorPool,
}

impl Schema {
    pub fn from_descriptor_set(bytes: &[u8]) -> Result<Self, ProtoError> {
        let pool = DescriptorPool::decode(bytes).map_err(|err| {
            ProtoError::Message(format!("failed to create file descriptors: {err}"))
        })?;
        Ok(Self { pool })
    }

    pub fn from_file_descriptor_protos(files: &[Vec<u8>]) -> Result<Self, ProtoError> {
        let mut pool = DescriptorPool::new();
        let mut seen = std::collections::BTreeSet::new();
        for file in files {
            let name = reflected_file_name(file)?;
            if !seen.insert(name) {
                continue;
            }
            pool.decode_file_descriptor_proto(file.as_slice())
                .map_err(|err| {
                    ProtoError::Message(format!("failed to decode reflected descriptor: {err}"))
                })?;
        }
        Ok(Self { pool })
    }

    pub fn load_descriptor_set_file(path: &str) -> Result<Self, FetchError> {
        let bytes = std::fs::read(path).map_err(|err| {
            FetchError::Message(format!("failed to read descriptor set file: {err}"))
        })?;
        Self::from_descriptor_set(&bytes).map_err(|err| FetchError::Message(err.to_string()))
    }

    pub fn find_method(&self, full_name: &str) -> Result<MethodDescriptor, ProtoError> {
        let (service_name, method_name) = split_method_name(full_name)?;
        let service = self
            .pool
            .get_service_by_name(service_name)
            .ok_or_else(|| ProtoError::Message(format!("service not found: {service_name}")))?;
        let method = service
            .methods()
            .find(|method| method.name() == method_name);
        method.ok_or_else(|| {
            ProtoError::Message(format!(
                "method {method_name} not found in service {service_name}"
            ))
        })
    }

    pub fn find_service(&self, name: &str) -> Option<ServiceDescriptor> {
        self.pool.get_service_by_name(normalize_symbol_name(name))
    }

    pub fn find_message(&self, name: &str) -> Option<MessageDescriptor> {
        self.pool.get_message_by_name(normalize_symbol_name(name))
    }

    pub fn messages(&self) -> Vec<String> {
        let mut messages: Vec<_> = self
            .pool
            .all_messages()
            .map(|message| message.full_name().to_string())
            .collect();
        messages.sort();
        messages
    }

    pub fn services(&self) -> Vec<String> {
        let mut services: Vec<_> = self
            .pool
            .services()
            .map(|service| service.full_name().to_string())
            .collect();
        services.sort();
        services
    }
}

pub fn load_local_schema(cli: &crate::cli::Cli) -> Result<Option<Schema>, FetchError> {
    let proto_files = proto_file_paths(&cli.proto_files);
    if !proto_files.is_empty() {
        return compile_protos(&proto_files, &cli.proto_imports)
            .map(Some)
            .map_err(|err| FetchError::Message(err.to_string()));
    }
    cli.proto_desc
        .as_deref()
        .map(Schema::load_descriptor_set_file)
        .transpose()
}

pub fn proto_file_paths(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn compile_protos(
    proto_files: &[String],
    import_paths: &[String],
) -> Result<Schema, ProtoError> {
    let descriptor_path = TempDescriptorSet::create()?;
    let mut command = Command::new("protoc");
    command
        .arg(format!(
            "--descriptor_set_out={}",
            descriptor_path.path().display()
        ))
        .arg("--include_imports");

    if import_paths.is_empty() {
        for dir in default_proto_import_paths(proto_files)? {
            command.arg(format!("-I={}", dir.display()));
        }
    } else {
        for import in import_paths {
            command.arg(format!("-I={import}"));
        }
    }
    for file in proto_files {
        command.arg(file);
    }

    let output = command.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            ProtoError::ProtocNotFound
        } else {
            ProtoError::Message(format!("failed to run protoc: {err}"))
        }
    })?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if message.is_empty() {
            exit_status_message(output.status)
        } else {
            message
        };
        return Err(ProtoError::Protoc(message));
    }

    let bytes = std::fs::read(descriptor_path.path())
        .map_err(|err| ProtoError::Message(format!("failed to read descriptor set file: {err}")))?;
    Schema::from_descriptor_set(&bytes)
}

pub fn method_for_url(schema: &Schema, url: &url::Url) -> Result<MethodDescriptor, FetchError> {
    schema
        .find_method(url.path().trim_start_matches('/'))
        .map_err(|err| FetchError::Message(err.to_string()))
}

pub fn normalize_symbol_name(symbol: &str) -> &str {
    symbol.trim_start_matches(['/', '.'])
}

fn split_method_name(full_name: &str) -> Result<(&str, &str), ProtoError> {
    let full_name = normalize_symbol_name(full_name);
    if let Some((service, method)) = full_name.rsplit_once('/') {
        if !service.is_empty() && !method.is_empty() {
            return Ok((service, method));
        }
    } else if let Some((service, method)) = full_name.rsplit_once('.')
        && !service.is_empty()
        && !method.is_empty()
    {
        return Ok((service, method));
    }
    Err(ProtoError::Message(format!(
        "invalid method name format: {full_name} (expected 'Service/Method' or 'Service.Method')"
    )))
}

fn default_proto_import_paths(proto_files: &[String]) -> Result<Vec<PathBuf>, ProtoError> {
    let cwd = std::env::current_dir()
        .map_err(|err| ProtoError::Message(format!("failed to get current directory: {err}")))?;
    let mut seen = std::collections::HashSet::new();
    let mut dirs = Vec::new();
    for file in proto_files {
        let path = Path::new(file);
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let abs = if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            cwd.join(dir)
        };
        if seen.insert(abs.clone()) {
            dirs.push(abs);
        }
    }
    Ok(dirs)
}

fn exit_status_message(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit status {code}"),
        None => "process terminated by signal".to_string(),
    }
}

struct TempDescriptorSet {
    path: PathBuf,
}

impl TempDescriptorSet {
    fn create() -> Result<Self, ProtoError> {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        for attempt in 0..100 {
            let path = temp_dir.join(format!("fetch-proto-{pid}-{nanos}-{attempt}.pb"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    drop(file);
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(ProtoError::Message(format!(
                        "failed to create temp file: {err}"
                    )));
                }
            }
        }
        Err(ProtoError::Message(
            "failed to create temp file: too many collisions".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDescriptorSet {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
