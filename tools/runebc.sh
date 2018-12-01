#!/bin/sh

set -e

INCLUDE=fasmg-ebc/include fasmg $1 $1.efi
ebcvm ./$1.efi
