Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Rust TDQuote Generation SampleCode
================================================

## Linux
Supported operating systems:
* Ubuntu* 18.04 LTS Desktop 64bits
* Ubuntu* 18.04 LTS Server 64bits
* Ubuntu* 20.04 LTS Server 64bits
* Red Hat Enterprise Linux Server release 8.2 64bits
* CentOS 8.2 64bits

Requirements:
* make
* gcc
* g++
* bash shell
* clang
* Rust and Cargo

Prerequisite:
* Intel(R) SGX SDK

*Note that you need to install **libtdx-attest-dev** for this package.*

Build and run *RustTDQuoteGenerationSample* to generate a TD quote

```
$ cargo build
$ ./target/debug/app
```

You can also combine building and running with a single Cargo command:
```
$ cargo run
```
