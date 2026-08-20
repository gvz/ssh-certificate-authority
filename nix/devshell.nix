{ pkgs, rust-toolchain }:
with pkgs;
mkShell {
  buildInputs = [
    rust-toolchain
    pre-commit
    llvm
    clang
    libclang
    llvmPackages.libclang.lib
    lldb
    openssl
    openssl.dev
    cargo-nextest
    pkg-config
    cargo-vet
    cargo-audit
    cargo-fuzz
    systemd
    pcsclite
    pam
    gnumake
    grcov
    act
    mdbook
  ];
  shellHook = ''
    export LIBCLANG_PATH="${llvmPackages.libclang.lib}/lib";
    export PATH="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin:$PATH"
  '';
  RUST_SRC_PATH = "${rust-toolchain}/lib/rustlib/src/rust/library";
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
    pkgs.llvmPackages.libclang.lib
    pkgs.pam
    pkgs.systemd
    pkgs.stdenv.cc.cc.lib
  ];
}
