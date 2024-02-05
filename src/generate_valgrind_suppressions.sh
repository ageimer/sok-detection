#!/bin/bash

# input binary
binary=$1

# output suppression file
shift; output=$1

# generate suppressions
valgrind --tool=memcheck --error-limit=no --num-callers=64 --default-suppressions=yes --gen-suppressions=all --log-file=${output} ${binary}

# unfortunately, regular valrgind errors are reported in the same file, so we remove them
sed -i '/^==[0-9]*==/d' ${output}
sed -i '/^--[0-9]*--/d' ${output}
