{
  pkgs,
  fenix,
  naersk,
  system,
}:
let
  rust-toolchain = fenix.packages.${system}.latest.withComponents [
    "rustc"
    "cargo"
    "rustfmt"
    "clippy"
    "rust-src"
    "llvm-tools-preview"
  ];

  naersk-lib = pkgs.callPackage naersk {
    cargo = rust-toolchain;
    rustc = rust-toolchain;
  };

  common = {
    pname = "ssh_ca_server";
    version = "0.1.0";

    release = true;

    src = ./..;
    nativeBuildInputs = with pkgs; [
      autoPatchelfHook
    ];
    buildInputs = with pkgs; [
      llvm
      clang
      libclang
      llvmPackages.libclang.lib
      lldb
      pkg-config
      systemd
      pcsclite
      pam
    ];
    LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
    LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
      pkgs.llvmPackages.libclang.lib
      pkgs.pam
      pkgs.systemd
    ];
  };

  app = naersk-lib.buildPackage (common // { doCheck = false; });

  test_app = naersk-lib.buildPackage (
    common
    // {
      doCheck = true;
      cargoTestOptions = x: x ++ [ "--features test_auth" ];
    }
  );
in
{
  inherit
    rust-toolchain
    naersk-lib
    common
    app
    test_app
    ;
}
