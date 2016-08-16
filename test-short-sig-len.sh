#!/bin/bash

cd test

for f in `ls test-sig-*-*`; do
	od -t x1 -j 47 -N 1 $f | grep -q '00$' && echo "$f is short sig"
	od -t x1 -j 95 -N 1 $f | grep -q '00$' && echo "$f is short sig"
done
