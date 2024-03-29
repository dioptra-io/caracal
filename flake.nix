{
  description = "A fast ICMP/UDP IPv4/v6 Paris traceroute and ping engine";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-22.11";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in {
        packages = {
          caracal = pkgs.stdenv.mkDerivation {
            pname = "caracal";
            version = "0.15.3";
            src = self;
            nativeBuildInputs = [
              pkgs.cmake
            ];
            buildInputs = [
              pkgs.cxxopts
              pkgs.libtins
              pkgs.libpcap
              pkgs.spdlog
            ];
            cmakeFlags = [
              "-DWITH_BINARY=ON"
            ];
          };
        };
        defaultPackage = self.packages.${system}.caracal;
      }
    );
}
