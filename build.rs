use std::path::PathBuf;

use serde::Deserialize;

static RAW_GRAMMARS: &str = include_str!("grammars/grammars.toml");

#[derive(Deserialize)]
struct Grammars {
    language: Vec<Language>,
}

#[derive(Deserialize)]
struct Language {
    name: String,
    files: Vec<String>,
    headers: Vec<String>,
}

fn main() {
    let grammars: Grammars = toml::from_str(RAW_GRAMMARS).unwrap();
    for language in grammars.language {
        let dir: PathBuf = ["grammars", &language.name].iter().collect();

        let mut build = cc::Build::new();
        let include = if language.name.as_str() == "xml" {
            dir.join("xml").join("src")
        } else {
            dir.join("src")
        };
        build.include(include);

        for file in language.files {
            let path = dir.join(file);
            build.file(&path);
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
        }
        for header in language.headers {
            let path = dir.join(header);
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
        }

        build
            .include(&dir)
            .flag_if_supported("-Wno-implicit-fallthrough")
            .flag_if_supported("-Wno-sign-compare")
            .flag_if_supported("-Wno-trigraphs")
            .flag_if_supported("-Wno-unused-but-set-variable")
            .flag_if_supported("-Wno-unused-function")
            .flag_if_supported("-Wno-unused-parameter")
            .flag_if_supported("-Wno-unused-value")
            .compile(&format!("tree-sitter-{}", language.name));
    }
}
