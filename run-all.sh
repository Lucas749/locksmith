#!/bin/zsh

if ! cargo build --release; then
    echo "Build failed, aborting..."
    exit 1
fi

ttab -w -t "Party 1" "cd '$(pwd)' && ./run-party.sh 1"
sleep 1  # Give the first window time to open
ttab -g -t "Party 2" "cd '$(pwd)' && ./run-party.sh 2"
sleep 1  # Give the second window time to open
ttab -g -t "Party 3" "cd '$(pwd)' && ./run-party.sh 3"
