fn main() {
    // Real libdbus-1.so.3 embeds this SONAME; anything already linked
    // against it has that exact string baked into its ELF NEEDED entry,
    // so ours has to match for the dynamic linker to consider it the same
    // library once it's installed as `libdbus-1.so.3`.
    println!("cargo:rustc-link-arg=-Wl,-soname,libdbus-1.so.3");
}
