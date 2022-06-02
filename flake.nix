{
  description = "A fast ICMP/UDP IPv4/v6 Paris traceroute and ping engine";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/f06cec9564a2fc6b85d92398551a0c059fc4db86";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlay = final: prev: {
          boostWithZstd = prev.boost.overrideAttrs (old: {
            buildInputs = old.buildInputs ++ [prev.zstd];
          });
        };
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ overlay ];
        };
      in {
        packages = {
          caracal = pkgs.stdenv.mkDerivation {
            pname = "caracal";
            version = "0.11.1";
            src = self;
            nativeBuildInputs = [
              pkgs.cmake
            ];
            buildInputs = [
              pkgs.boostWithZstd
              pkgs.cxxopts
              pkgs.libtins
              pkgs.libpcap
              pkgs.spdlog
            ];
            cmakeFlags = [
              "-DWITH_CONAN=OFF"
              "-DWITH_PYTHON=OFF"
              "-DWITH_TESTS=OFF"
            ];
          };
        };
        defaultPackage = self.packages.${system}.caracal;
      }
    );
}
