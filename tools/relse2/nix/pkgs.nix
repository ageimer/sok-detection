let
  sources = import ./sources.nix {};
  overlay = self: super: {
    niv = (import sources.niv {}).niv;
    ocamlPackages_for_binsec = self.ocaml-ng.ocamlPackages_4_09.overrideScope'(
    oself: osuper: {
      unisim_archisec = oself.callPackage ./unisim_archisec.nix {};
    });
    binsec = self.ocamlPackages_for_binsec.callPackage ./binsec.nix {};
    binsec_appimage = super.callPackage ./bundle.nix {};
    inherit (import sources.nixpkgs_2003 {}) appimage-run;
  };
  pkgs = import sources.nixpkgs { overlays = [ overlay ]; };
in
  pkgs
