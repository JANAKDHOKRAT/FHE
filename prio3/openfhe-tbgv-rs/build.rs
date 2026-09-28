//! Compiles the threshold-BGV C++ shim and links OpenFHE.
//!
//! Environment overrides:
//!   OPENFHE_DIR          base prefix (default /usr/local)
//!   OPENFHE_INCLUDE_DIR  header dir (default $OPENFHE_DIR/include/openfhe)
//!   OPENFHE_LIB_DIR      library dir (default $OPENFHE_DIR/lib)
use std::env;

fn main() {
    let base = env::var("OPENFHE_DIR").unwrap_or_else(|_| "/usr/local".into());
    let include_dir =
        env::var("OPENFHE_INCLUDE_DIR").unwrap_or_else(|_| format!("{base}/include/openfhe"));
    let lib_dir = env::var("OPENFHE_LIB_DIR").unwrap_or_else(|_| format!("{base}/lib"));

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
