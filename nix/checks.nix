{
  pkgs,
  nixpkgs,
  naersk-lib,
  common,
  test_app,
  sshCaServerModule,
}:
{
  cargo-tests = test_app;

  end_to_end_test = import ./../tests/end_to_end_test/test.nix {
    inherit nixpkgs;
    inherit sshCaServerModule;
  };

  fuzz-smoke-test =
    let
      fuzzSrc = pkgs.stdenv.mkDerivation {
        name = "fuzz-src";
        src = ./..;
        phases = [
          "unpackPhase"
          "patchPhase"
          "installPhase"
        ];
        installPhase = ''
          # Create a directory layout where the fuzz workspace is at the
          # root (so naersk finds its Cargo.lock) but the parent crate
          # is available via the path dependency.
          mkdir -p $out
          cp -r . $out/parent
          # Copy fuzz contents to root level
          cp fuzz/Cargo.toml $out/Cargo.toml
          cp fuzz/Cargo.lock $out/Cargo.lock
          cp -r fuzz/fuzz_targets $out/fuzz_targets
          # Rewrite the path dependency from ".." to "./parent"
          substituteInPlace $out/Cargo.toml \
            --replace-fail 'path = ".."' 'path = "./parent"'
          # Fix the bin paths
          substituteInPlace $out/Cargo.toml \
            --replace-fail 'path = "fuzz_targets/' 'path = "fuzz_targets/'
        '';
      };
    in
    naersk-lib.buildPackage {
      pname = "ssh_ca_server-fuzz-smoke";
      src = fuzzSrc;
      nativeBuildInputs = common.nativeBuildInputs;
      buildInputs = common.buildInputs;
      LIBCLANG_PATH = common.LIBCLANG_PATH;
      LD_LIBRARY_PATH = common.LD_LIBRARY_PATH;
      doCheck = false;
      singleStep = true;
      RUSTC_BOOTSTRAP = "1";
    };
}
