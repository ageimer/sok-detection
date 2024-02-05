let
  pkgs = import ./pkgs.nix;
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    niv
    boolector
    z3
    cvc4
    yices
    bitwuzla
    ocamlPackages_for_binsec.merlin
    ocamlPackages_for_binsec.ocaml-lsp
    ocamlPackages_for_binsec.odoc
    ocamlformat_0_19_0
    appimage-run
  ];
  inputsFrom = [ pkgs.binsec ];
}
