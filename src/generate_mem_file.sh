#!/bin/bash

binary=$1

# input memory file (specifies values for esp and ebp)
shift; input=$1

# output memory file
shift; output=$1

# list of symbols to check
shift; symbols=$@

cp $input $output

for sym in $symbols; do
    nm_out=($(nm -S ${binary} | grep "${sym}" | sed s/'\w* \w*$'//))
    addr=${nm_out[0]}
    size=${nm_out[1]}
    echo -e "\n# ${sym}\n@[0x${addr},$((16#${size}))] from_file;" >> $output
done
