{ lib, buildDunePackage, odoc }:
let sources = import ../nix/sources.nix { }; in
buildDunePackage {
  pname = "unisim_archisec";
  version = sources.unisim_archisec.rev or "local";
  src = sources.unisim_archisec;

  useDune2 = true;

  nativeBuildInputs = [ odoc ];
}
