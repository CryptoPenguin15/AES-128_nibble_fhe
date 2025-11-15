fn main() {
    let has_cuda = std::process::Command::new("nvcc")
        .arg("--version")
        .output()
        .is_ok();

    if has_cuda {
        println!("cargo:rustc-cfg=has_cuda");
    }
}
