/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let prebuilt = manifest_dir.join("docsrs").join("prebuilt-bindings.rs");
    let provenance_file = manifest_dir.join("docsrs").join("bindings-provenance.txt");
    let in_package = is_package_verify_dir(&manifest_dir);
    // Never regenerate inside the verification copy: the publish guard below must check
    // the files that were actually packaged, not ones rewritten during verification.
    let update_docsrs = env::var("DCAP_QV_UPDATE_DOCSRS_BINDINGS").is_ok() && !in_package;

    // Env changes must re-run this script, else a cached run takes the wrong branch.
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=DCAP_QV_UPDATE_DOCSRS_BINDINGS");

    // docs.rs has no network, so libsgx-dcap-quote-verify-dev (the C headers) and the
    // shared library are absent; use the bindings shipped in the tarball instead, and
    // report the dev package they were generated from (recorded in the sidecar).
    // Not in the package-verification copy, though: the publish guard below must run.
    if env::var("DOCS_RS").is_ok() && !in_package {
        println!("cargo:rerun-if-changed=docsrs/prebuilt-bindings.rs");
        println!("cargo:rerun-if-changed=docsrs/bindings-provenance.txt");
        std::fs::copy(&prebuilt, out_path.join("bindings.rs")).expect(
            "Couldn't stage docs.rs fallback docsrs/prebuilt-bindings.rs; regenerate it with \
             `DCAP_QV_UPDATE_DOCSRS_BINDINGS=1 cargo build` and republish",
        );
        let source = std::fs::read_to_string(&provenance_file)
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned());
        write_provenance(&out_path, &source);
        return;
    }

    // Tell cargo to tell rustc to link the system
    // sgx-dcap-quoteverify shared library.
    println!("cargo:rustc-link-lib=sgx_dcap_quoteverify");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=bindings.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut builder = bindgen::Builder::default();

    // Set sdk to search path if SGX_SDK is in environment variable
    if let Ok(val) = env::var("SGX_SDK") {
        let mut sdk_inc = String::from("-I");
        sdk_inc.push_str(&val);
        sdk_inc.push_str("/include/");
        // Include search path
        builder = builder.clang_arg(sdk_inc);
    }

    let bindings = builder
        // The input header we would like to generate
        // bindings for.
        .header("bindings.h")
        // C enums returned by the QVL across the FFI boundary need
        // newtype_enum, not rustified_enum: the library is loaded from
        // the system (`cargo:rustc-link-lib=sgx_dcap_quoteverify`) and
        // may be a newer version than the headers used at build time.
        // If such a library ever returns a discriminant the bindgen-
        // generated Rust `enum` does not list, materialising that value
        // as the Rust enum is instant UB (invalid-enum-variant).
        // `newtype_enum` keeps the underlying integer representation
        // while still exposing the named values as associated constants,
        // so unknown discriminants are merely unrecognised, not UB.
        .newtype_enum("_quote3_error_t")
        .newtype_enum("_sgx_ql_qv_result_t")
        // Input-only enums (Rust -> C) keep `rustified_enum`: Rust only
        // ever constructs the known variants, so there is no invalid-
        // discriminant hazard, and a closed enum preserves type safety
        // on the safe-wrapper API surface.
        .rustified_enum("_sgx_ql_request_policy")
        .rustified_enum("sgx_qv_path_type_t")
        // Disable Debug trait for packed C structures
        .no_debug("_quote_t")
        .no_debug("_sgx_ql_auth_data_t")
        .no_debug("_sgx_ql_certification_data_t")
        .no_debug("_sgx_ql_ecdsa_sig_data_t")
        .no_debug("_sgx_quote3_t")
        .no_debug("_sgx_ql_att_key_id_param_t")
        // Enable Default trait
        .derive_default(true)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings; is libsgx-dcap-quote-verify-dev (the C headers) installed?");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Only query the package manager when regenerating the fallback (release-time);
    // a normal consumer build just records that it used the local system headers.
    let source = if update_docsrs {
        dcap_dev_package()
    } else {
        "local system headers".to_owned()
    };
    write_provenance(&out_path, &source);

    // Release-only: refresh the gitignored docs.rs fallback (prebuilt bindings plus the
    // provenance sidecar) from these headers so the packaged tarball rebuilds on docs.rs.
    if update_docsrs {
        std::fs::create_dir_all(prebuilt.parent().unwrap())
            .expect("Couldn't create docsrs/ directory");
        std::fs::write(&provenance_file, format!("{source}\n"))
            .expect("Couldn't write docsrs/bindings-provenance.txt");
        bindings
            .write_to_file(&prebuilt)
            .expect("Couldn't write docsrs/prebuilt-bindings.rs");
        println!("cargo:warning=docs.rs fallback bindings generated from {source}");
    }

    // Watch the fallback (bindings and provenance sidecar) so deleting/staling either
    // re-runs this script (else a repeat flag build with an unchanged env sees a fresh
    // fingerprint and skips regen). Skip a file when it's legitimately absent (normal
    // dev tree) to avoid perpetual re-runs.
    if update_docsrs || prebuilt.exists() {
        println!("cargo:rerun-if-changed=docsrs/prebuilt-bindings.rs");
    }
    if update_docsrs || provenance_file.exists() {
        println!("cargo:rerun-if-changed=docsrs/bindings-provenance.txt");
    }

    // Self-policing: cargo publish/package builds from an extracted copy, where headers
    // exist too. Fail there if the shipped fallback is missing or stale.
    if in_package {
        let generated = bindings.to_string();
        match std::fs::read_to_string(&prebuilt) {
            Err(_) => panic!(
                "docs.rs fallback docsrs/prebuilt-bindings.rs is missing from the \
                 package; run `DCAP_QV_UPDATE_DOCSRS_BINDINGS=1 cargo build` before publishing"
            ),
            Ok(packaged) if packaged != generated => panic!(
                "docs.rs fallback docsrs/prebuilt-bindings.rs is stale; run \
                 `DCAP_QV_UPDATE_DOCSRS_BINDINGS=1 cargo build` before publishing"
            ),
            Ok(_) => {}
        }
        // cargo package ignores an `include` entry that matches nothing, so check the
        // sidecar too, else docs.rs silently reports provenance "unknown". It must also
        // name the dev package installed now, i.e. the one the bindings were checked
        // against above.
        let expected = dcap_dev_package();
        match std::fs::read_to_string(&provenance_file) {
            Ok(s) if s.trim() == expected => {}
            Ok(s) if !s.trim().is_empty() => panic!(
                "docs.rs fallback docsrs/bindings-provenance.txt is stale ({:?}, installed: \
                 {expected:?}); run `DCAP_QV_UPDATE_DOCSRS_BINDINGS=1 cargo build` before \
                 publishing",
                s.trim()
            ),
            _ => panic!(
                "docs.rs fallback docsrs/bindings-provenance.txt is missing or empty; run \
                 `DCAP_QV_UPDATE_DOCSRS_BINDINGS=1 cargo build` before publishing"
            ),
        }
    }
}

// cargo package/publish verifies from `<target-dir>/package/<name>-<version>/`; match
// that layout rather than a literal `target/` so a custom CARGO_TARGET_DIR is covered.
fn is_package_verify_dir(manifest_dir: &Path) -> bool {
    let expected = format!(
        "{}-{}",
        env::var("CARGO_PKG_NAME").unwrap(),
        env::var("CARGO_PKG_VERSION").unwrap()
    );
    manifest_dir.file_name() == Some(OsStr::new(&expected))
        && manifest_dir.parent().and_then(Path::file_name) == Some(OsStr::new("package"))
}

// Emit the crate's DCAP_BINDINGS_PROVENANCE constant into $OUT_DIR.
fn write_provenance(out_path: &Path, source: &str) {
    std::fs::write(
        out_path.join("provenance.rs"),
        format!(
            "/// Where the compiled FFI bindings came from. For an ordinary build this is\n\
             /// always `\"local system headers\"`; a concrete DCAP dev package version only\n\
             /// appears in the docs.rs documentation, which uses the prebuilt fallback.\n\
             pub const DCAP_BINDINGS_PROVENANCE: &str = {source:?};\n"
        ),
    )
    .expect("Couldn't write provenance.rs");
}

// Best-effort: the installed DCAP dev package and version that supplied the C
// headers. Named `-dev` on Debian/Ubuntu, `-devel` on Fedora/RHEL.
fn dcap_dev_package() -> String {
    use std::process::Command;
    let queries: [(&str, &[&str]); 2] = [
        (
            "dpkg-query",
            &["-W", "-f=${Package} ${Version}", "libsgx-dcap-quote-verify-dev"],
        ),
        ("rpm", &["-q", "libsgx-dcap-quote-verify-devel"]),
    ];
    for (bin, args) in queries {
        if let Ok(out) = Command::new(bin).args(args).output() {
            if out.status.success() {
                let found = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                if !found.is_empty() {
                    return found;
                }
            }
        }
    }
    "unknown".to_owned()
}
