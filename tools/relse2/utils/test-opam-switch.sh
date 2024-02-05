#!/bin/sh
# test-opam-switch.sh is, as its name hints, a shell script facilitating the
# testing of new OCaml compiler versions, along with the dependencies needed to
# compile BINSEC


switch="$1"

echo "Testing OCaml version $switch ..."

opam switch create ${switch}
eval $(opam env)
opam pin add -yn .
opam install -y --deps-only binsec
opam install -y merlin

echo "----"
echo "Now run dune clean; dune build @install to test this OCaml version"
