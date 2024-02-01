fn main() {
    // println!("cargo:rerun-if-changed=build.rs");
    // println!("cargo:rustc-cfg=nightly");
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .csharp_dll_name("liabaflTestlib")
        .generate_csharp_file("libaflRenodeTest1.cs")
        .unwrap();
}
