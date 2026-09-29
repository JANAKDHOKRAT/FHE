//! Compiles the threshold-BGV C++ shim and links OpenFHE.
//!
//! Environment overrides:
//!   OPENFHE_DIR          base prefix (default /usr/local)
//!   OPENFHE_INCLUDE_DIR  header dir (default $OPENFHE_DIR/include/openfhe)
//!   OPENFHE_LIB_DIR      library dir (default $OPENFHE_DIR/lib)
//!
//! Version gate. The packed wire format rebuilds received ciphertexts
//! through OpenFHE's element and metadata accessors, so this crate builds
//! only against OpenFHE versions on the tested list below. To add a
//! version: build against it with the list extended locally, run
//! `cargo test --release` here and in `fhe-prio3` (the rebuild exactness
//! tests and the runtime self-test must pass), then extend the list. The
//! version is read from the CMake package file OpenFHE installs, and the
//! versioned shared libraries must be present next to it.
use std::env;
use std::path::Path;

const TESTED_OPENFHE_VERSIONS: &[&str] = &["1.3.1"];

fn installed_version(lib_dir: &str) -> String {
    let file = format!("{lib_dir}/OpenFHE/OpenFHEConfigVersion.cmake");
    let text = std::fs::read_to_string(&file)
        .unwrap_or_else(|e| panic!("cannot read {file} to determine the OpenFHE version: {e}"));
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("set(PACKAGE_VERSION"))
        .unwrap_or_else(|| panic!("{file} does not set PACKAGE_VERSION"));
    let v = line.split('"').nth(1).unwrap_or_else(|| panic!("cannot parse the version in {file}: {line}"));
    if v.is_empty() || !v.chars().all(|c| c.is_ascii_digit() || c == '.') {
        panic!("unexpected OpenFHE version string {v:?} in {file}");
    }
    v.to_string()
}

fn main() {
    let base = env::var("OPENFHE_DIR").unwrap_or_else(|_| "/usr/local".into());
    let include_dir =
        env::var("OPENFHE_INCLUDE_DIR").unwrap_or_else(|_| format!("{base}/include/openfhe"));
    let lib_dir = env::var("OPENFHE_LIB_DIR").unwrap_or_else(|_| format!("{base}/lib"));

    let version = installed_version(&lib_dir);
    if !TESTED_OPENFHE_VERSIONS.contains(&version.as_str()) {
        panic!(
            "OpenFHE {version} in {lib_dir} is not a tested version (tested: {TESTED_OPENFHE_VERSIONS:?}). \
             See the version gate at the top of openfhe-tbgv-rs/build.rs for how to add one."
        );
    }
    for lib in ["OPENFHEpke", "OPENFHEcore", "OPENFHEbinfhe"] {
        let file = format!("{lib_dir}/lib{lib}.so.{version}");
        if !Path::new(&file).exists() {
            panic!("{file} is missing: the libraries in {lib_dir} do not match OpenFHE {version}");
        }
    }
    println!("cargo:rustc-env=TBGV_OPENFHE_VERSION={version}");
    println!("cargo:rerun-if-changed={lib_dir}/OpenFHE/OpenFHEConfigVersion.cmake");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .opt_level(2)
        .file("wrapper/tbgv.cpp")
        .include(&include_dir)
        .include(format!("{include_dir}/core"))
        .include(format!("{include_dir}/pke"))
        .include(format!("{include_dir}/binfhe"))
        .define("MATHBACKEND", "4")
        .flag_if_supported("-fopenmp")
        .warnings(false);
    build.compile("tbgv");

    println!("cargo:rustc-link-search=native={lib_dir}");
    for lib in ["OPENFHEpke", "OPENFHEcore", "OPENFHEbinfhe"] {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }
    println!("cargo:rustc-link-lib=dylib=gomp");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rerun-if-changed=wrapper/tbgv.h");
    println!("cargo:rerun-if-changed=wrapper/tbgv.cpp");
    println!("cargo:rerun-if-env-changed=OPENFHE_DIR");
    println!("cargo:rerun-if-env-changed=OPENFHE_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=OPENFHE_LIB_DIR");
}
