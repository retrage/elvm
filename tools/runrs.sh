#!/bin/sh

set -e

tmp=`echo $1 | sed 's/\./_/g'`
cp $1 $tmp
rustc $tmp -o $1.exe
rm $tmp
./$1.exe
