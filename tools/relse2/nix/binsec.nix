{ lib
, nix-gitignore
, gmp
, mmap
, ocamlgraph
, zarith
, menhir
, llvm
, dune-site
, qtest
, ounit
, qcheck
, seq
, toml
, unisim_archisec
, buildDunePackage
}:
buildDunePackage {
  pname = "binsec";
  version = builtins.elemAt
		(builtins.match ".*version \"([^\"]*)\".*"
	  			(builtins.readFile ../dune-project))
		0;

  duneVersion = "3";

  src = nix-gitignore.gitignoreSource [
    ''
      # additionnal ignores
      /nix
    ''
  ]
    ./..;


  buildInputs = [
    gmp # for zarith
    ocamlgraph
    zarith
    menhir
    llvm
    unisim_archisec
    mmap
    dune-site
    qtest
    ounit
    qcheck
    seq
    toml
  ];
}
