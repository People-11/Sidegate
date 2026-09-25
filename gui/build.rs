// Builds ../core (Go) as a static library and links it in, so the whole app is one exe.
use std::{env, process::Command};

fn main() {
    let out = env::var("OUT_DIR").unwrap();
    let st = Command::new("go")
        .args(["build", "-buildmode=c-archive", "-trimpath", "-ldflags=-s -w"])
        // No inlining (smaller) except on the data path: packet stack, crypto, runtime.
        .args([
            "-gcflags=all=-l",
            "-gcflags=gvisor.dev/gvisor/...=",
            "-gcflags=crypto/...=",
            "-gcflags=runtime=",
        ])
        .arg("-o")
        .arg(format!("{out}/libgpcore.a"))
        .arg(".")
        .current_dir("../core")
        .status()
        .expect("go toolchain not found");
    assert!(st.success(), "go build failed");
    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static=gpcore");
    for lib in ["ws2_32", "winmm", "ntdll", "userenv", "bcrypt", "crypt32"] {
        println!("cargo:rustc-link-lib={lib}");
    }
    println!("cargo:rerun-if-changed=../core");

    // Exe icon: compile icon.rc with MinGW windres and link the COFF resource object directly.
    let res = format!("{out}/icon.res.o");
    let st = Command::new("windres")
        .args(["icon.rc", "-O", "coff", "-o", &res])
        .status()
        .expect("windres not found");
    assert!(st.success(), "windres failed");
    println!("cargo:rustc-link-arg-bins={res}");
    println!("cargo:rerun-if-changed=icon.ico");
    println!("cargo:rerun-if-changed=icon.rc");
}
