//! Build script: compile the OpenFHE C ABI wrapper and link the prebuilt
//! OpenFHE static libraries (MinGW64 toolchain).

use std::env;
use std::path::PathBuf;

fn find_gpp() -> PathBuf {
    // MSYS2 MinGW64 g++ is the canonical compiler for OpenFHE on Windows.
    let candidates = [
        r"C:\msys64\mingw64\bin\g++.exe",
        r"C:\msys64\ucrt64\bin\g++.exe",
        r"C:\msys64\clang64\bin\g++.exe",
    ];
    for c in candidates {
        if PathBuf::from(c).exists() {
            return PathBuf::from(c);
        }
    }
    PathBuf::from("g++")
}

fn main() {
    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"));
    let openfhe = manifest.join("../..").join("openfhe-development");

    let mut build = cc::Build::new();
    build.cpp(true);
    build.compiler(find_gpp());
    build.flag("-std=gnu++17");
    // Suppress warnings from OpenFHE's own headers (unused parameters etc.).
    build.flag("-w");
    build.opt_level(2);
    build.include(openfhe.join("src/core/include"));
    build.include(openfhe.join("src/pke/include"));
    build.include(openfhe.join("src/binfhe/include"));
    build.include(openfhe.join("third-party/cereal/include"));
    build.include(openfhe.join("build/src/core"));
    build.file("cpp/capi.cpp");
    build.compile("ppsc_fhe_capi");

    println!(
        "cargo:rustc-link-search=native={}",
        openfhe.join("build/lib").display()
    );
    println!("cargo:rustc-link-search=native=C:/msys64/mingw64/lib");
    println!("cargo:rustc-link-lib=static=OPENFHEpke_static");
    println!("cargo:rustc-link-lib=static=OPENFHEcore_static");
    println!("cargo:rustc-link-lib=static=OPENFHEbinfhe_static");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=winpthread");
    // libmingwex (pulled in by the default MSVCRT libs) references _fileno/_setmode
    // which live in ucrtbase; link it last (static) to satisfy the reference order.
    println!("cargo:rustc-link-arg=-Wl,-Bstatic,-lucrtbase,-Bdynamic");
    println!("cargo:rustc-link-arg=-Wl,-Bstatic,-lmoldname,-Bdynamic");
}
