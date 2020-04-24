#!/bin/bash
if [ "$#" -lt "1" ]; then
    echo usage: $0 logfile
    exit 1
fi

sed 's/^\[FATAL.*\](\(.*\))Catch \(.*\) from \(.*\)$/\2 \1 \3/g' $1 \
    | sed 's/\.sh\...../\.sh/g' | sort -u | wc -l
