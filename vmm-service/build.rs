// vmm-service/build.rs
fn main() {
    // Set a simple version string
    println!("cargo:rustc-env=BUILD_VERSION=0.1.0");
}
