// build.rs
use std::{env, process::Command, str};

fn main() {
    // Let the user override if they really want to
    if let Ok(forced) = env::var("CXXSTDLIB") {
        println!("cargo:rustc-link-lib={forced}");
        return;
    }

    let target = env::var("TARGET").unwrap_or_default();

    // ✅  macOS always ships libc++, so link with -lc++
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
        return;
    }

    // ❌  MSVC ABI has no __cxa_demangle; bail out gracefully
    if target.contains("windows-msvc") {
        println!("cargo:warning=__cxa_demangle is not available on MSVC targets");
        return;
    }

    // ----------  Linux / *BSD / other Unix  ----------
    // Ask the host compiler where libc++.so would live.
    // If we get back an actual path (not just the literal filename),
    // we assume libc++ is present and usable.
    let compiler = env::var("CXX").unwrap_or_else(|_| "c++".into());
    let has_libcxx = Command::new(&compiler)
        .arg("-print-file-name=libc++.so")
        .output()
        .ok()
        .and_then(|o| {
            let path = str::from_utf8(&o.stdout).ok()?.trim();
            if path.is_empty() || path.ends_with("libc++.so") {
                None
            } else {
                Some(())
            }
        })
        .is_some();

    if has_libcxx {
        println!("cargo:rustc-link-lib=c++");
    } else {
        // default to GCC's libstdc++
        println!("cargo:rustc-link-lib=stdc++");
    }
}
