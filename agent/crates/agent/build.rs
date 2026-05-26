fn main() {
    // Expose the Rust target triple of the current build (e.g. "aarch64-apple-darwin")
    // to the binary as BUILD_TARGET. Used to populate AgentInfo.target_triple and
    // to look up the matching update artifact on the server side.
    let target = std::env::var("TARGET").expect("cargo must set TARGET");
    println!("cargo:rustc-env=BUILD_TARGET={}", target);
    println!("cargo:rerun-if-env-changed=TARGET");
}
