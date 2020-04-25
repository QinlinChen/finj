#!/bin/bash
if [ "$#" -lt "1" ]; then
    echo usage: $0 logfile
    exit 1
fi

grep -E '^\[FATAL.*\]\(.*\)Catch [[:alpha:]]* from [[:digit:]]*$' $1 \
	| sed -r 's/^\[FATAL.*\]\((.*)\)Catch (.*) from (.*)$/\2 \1 \3/g' \
    | sed 's/\.sh\...../\.sh/g' | sort -u
