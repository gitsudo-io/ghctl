#!/bin/bash

# The following lines merely split the input arguments by spaces 
# then pass them as individual arguments to ghctl. This allows the action to accept
# a single string of arguments but still pass them to ghctl as individual arguments.
IFS=' '; ARGS=(${@// / }); unset IFS;
set --
for a in "${ARGS[@]}"; do
    set -- "$@" "$a"
done
/usr/local/bin/ghctl "$@"
