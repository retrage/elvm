#!/bin/sh

set -e

$name=`basename -s .rs $1 | xargs basename -s .eir`
mkdir -p "/tmp/$name/src"
cp $1 "/tmp/$name/src/main.rs"
echo "[package]\n" >> "/tmp/$name/Cargo.toml"
echo "name = \"$name\"\n" >> "/tmp/$name/Cargo.toml"
echo "version = \"0.1.0\"\n" >> "/tmp/$name/Cargo.toml"
echo "\n" >> "/tmp/$name/Cargo.toml"
echo "[dependencies]\n" >> "/tmp/$name/Cargo.toml"
echo "lib = \"0.2\"" >> "/tmp/$name/Cargo.toml"
cd "/tmp/$name"
cargo run --release --quiet
