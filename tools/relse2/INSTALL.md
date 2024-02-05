# Installing BINSEC from sources

The latest version of `binsec` is available on GitLab:
https://git.frama-c.com/binary/binsec.  
The latest version of `unisim_archisec` is available on GitLab:
https://git.frama-c.com/binary/unisim_archisec.

A convenient way to build `unisim_archisec` together with `binsec` is to
put `unisim_archisec` directory inside the `binsec` directory.
 ```console
$ git clone https://git.frama-c.com/binary/binsec.git
$ cd binsec
$ git clone https://git.frama-c.com/binary/unisim_archisec.git
 ```
The latest version of `bitwuzla` OCaml binding is available on GitHub:
https://github.com/bitwuzla/ocaml-bitwuzla

The same as before, the simplest way to compile `binsec` with native
`bitwuzla` support is to put `ocaml-bitwuzla` directory inside the `binsec`
one.
```console
$ cd binsec
$ git clone --recurse-submodules https://github.com/bitwuzla/ocaml-bitwuzla.git
```
:information_source: It is still possible to get the submodules after a normal `clone` (i.e. w/o `--recurse-submodules`) with the following.
```console
$ (cd ocaml-bitwuzla && git submodules init && git submodules update)
```

#### Dependencies

Dependencies can be automatically installed via
[*opam*](https://opam.ocaml.org/doc/Install.html).  
```bash
$ opam depext -i zarith
$ opam install dune menhir ocamlgraph
$ opam install bitwuzla # optional -- for native SMT solver binding
```

##### System

- [GMP v6.1 (GNU Multi-Precision arithmetic library)](https://gmplib.org)
- [OCaml >= 4.08](https://github.com/ocaml/ocaml)

##### OCaml

- [dune >= 3.0](https://github.com/ocaml/dune)
- [menhir](https://gitlab.inria.fr/fpottier/menhir)
- [ocamlgraph >= 1.8.5](https://github.com/backtracking/ocamlgraph)
- [zarith >= 1.4](https://github.com/ocaml/Zarith)
- *[unisim_archisec](https://github.com/binsec/unisim_archisec) (optional)*
- [ocamlformat](https://github.com/ocaml-ppx/ocamlformat) (*format*)
- [odoc](https://github.com/ocaml/odoc) (*documentation*)
- [qcheck](https://github.com/c-cube/qcheck) (*test*)
- [ounit2](https://github.com/gildor478/ounit) (*test*)

## Build instructions

#### With `make`

[Makefile](Makefile) is a wrapper around `dune` build system.  
When `opam` is available, using the command `make` will automatically install the missing dependencies.

---
:information_source: **Local opam switch**  
If `opam` is available, using the following command will create a new OCaml switch inside the BINSEC tree.
```bash
OCAML_COMPILER=4.08.1 make switch
```
A local switch makes the installation of dependencies, including ocaml supported version, not impacting the system wide ocaml configuration.  
*Doing so, everything installed will be readily available but only inside the BINSEC directory.*

---

Run the following in order to build the `binsec` executable:
```bash
make
```
Then run the following in order to install `binsec` in the current switch:
```bash
make install
```

#### With `dune`

Make sure the above dependencies are available.

Run the following in order to build `binsec` executable:
```bash
dune build @install
```

`binsec` executable can be found in
`_build/install/default/bin`.

Run the following in order to install `binsec` in the current switch:
```bash
dune install
```
Or use it locally with:
```bash
dune exec -- binsec [...]
```
