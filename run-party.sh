#!/bin/zsh

if [ $# -eq 0 ]; then
    echo "Error: Party number (n) not provided"
    echo "Usage: $0 <party_number>"
    exit 1
fi

n=$1

echo "Running test for party $n..."
RUST_BACKTRACE=1 target/release/locksmith --config p$n.toml