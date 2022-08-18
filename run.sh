#!/bin/bash
cargo b --release
ext=$?
if [[ $ect -ne 0 ]]; then
    exit $ext
fi
sudo setcap cap_net_admin=eip ./target/release/tcpRust
./target/release/tcpRust &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
