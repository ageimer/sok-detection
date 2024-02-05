{ path
, lib
, makeWrapper
, runCommand
, binsec
, z3
, boolector
, yices
, cvc4
, busybox
, bitwuzla
}:
let
  nix-bundle = (import ./sources.nix {}).nix-bundle;
  utils = import (nix-bundle + "/appimage-top.nix") { nixpkgs' = path; };
  content = runCommand "bundle-content" { nativeBuildInputs = [ makeWrapper ]; } ''
    mkdir -p $out/bin
    makeWrapper ${binsec}/bin/binsec $out/bin/binsec \
    --prefix PATH : ${lib.makeBinPath [ z3 boolector yices cvc4 bitwuzla ]}
    # for /bin/sh for system()
    ln -s ${busybox}/bin/sh $out/bin/sh
    install -D ${../binsec.desktop} $out/share/applications/binsec.desktop
    install -D ${../binsec.png} $out/share/icons/hicolor/256x256/apps/binsec.png
  '';
  image = utils.appimage (
    utils.appdir {
      name = "binsec";
      target = content;
    }
  );
in
image
