use std::path::PathBuf;

struct Grammar {
    name: &'static str,
    prefix: Option<&'static str>,
    files: &'static [&'static str],
}

const GRAMMARS: &[Grammar] = &[
    Grammar {
        name: "json",
        prefix: None,
        files: &["parser.c"],
    },
    Grammar {
        name: "xml",
        prefix: Some("xml"),
        files: &["parser.c", "scanner.c"],
    },
];

fn main() {
    for grammer in GRAMMARS {
        let mut paths = vec!["grammars", grammer.name];
        if let Some(prefix) = grammer.prefix {
            paths.push(prefix);
        }
        paths.push("src");
        let dir: PathBuf = paths.iter().collect();

        let mut build = cc::Build::new();
        for file in grammer.files {
            build.file(dir.join(file));
        }
        build
            .include(&dir)
            .flag_if_supported("-Wno-implicit-fallthrough")
            .flag_if_supported("-Wno-trigraphs")
            .flag_if_supported("-Wno-unused-but-set-variable")
            .flag_if_supported("-Wno-unused-parameter")
            .flag_if_supported("-Wno-unused-value")
            .compile(&format!("tree-sitter-{}", grammer.name));

        let header_path = dir.join("tree_sitter").join("parser.h");
        println!("cargo:rerun-if-changed={}", header_path.to_str().unwrap());
    }
}
