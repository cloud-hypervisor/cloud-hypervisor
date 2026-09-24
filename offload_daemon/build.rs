use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/qpl_shim.c");
    println!("cargo:rerun-if-env-changed=QPL_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=QPL_LIB_DIR");

    if env::var_os("CARGO_FEATURE_QPL").is_none() {
        return;
    }

    let include_dir =
        env::var("QPL_INCLUDE_DIR").unwrap_or_else(|_| "/usr/local/include".to_owned());
    let library_dir = env::var("QPL_LIB_DIR").unwrap_or_else(|_| "/usr/local/lib64".to_owned());
    cc::Build::new()
        .file("src/qpl_shim.c")
        .include(include_dir)
        .warnings(true)
        .compile("qpl_shim");
    println!("cargo:rustc-link-search=native={library_dir}");
    println!("cargo:rustc-link-lib=static=qpl");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=dl");
}
