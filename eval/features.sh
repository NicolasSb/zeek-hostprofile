#!/bin/sh
# Usage: features.sh DATA OUT
# Runs the package on every evaluation capture, in the pinned Zeek image,
# with fixed hash seeds (HyperLogLog and Bloom filters are seeded).
set -e
data=$(realpath "$1") out=$(realpath "$2")
eval=$(dirname "$(realpath "$0")")
scripts=$(realpath "$eval/../scripts")
image=zeek/zeek:9.0.0

run() {
	mkdir -p "$out/$1"
	docker run --rm -u "$(id -u):$(id -g)" -v "$scripts":/pkg:ro -v "$data":/data:ro \
		-v "$eval":/eval:ro -v "$out/$1":/out -w /out $image \
		zeek -C -G /eval/zeek.seed -r "/data/$2" /pkg $3 >"$out/$1/zeek.stderr" 2>&1
}

for day in Monday Tuesday Wednesday Thursday Friday; do
	[ -e "$data/$day-WorkingHours.pcap" ] || continue
	run "$(echo $day | tr A-Z a-z)" "$day-WorkingHours.pcap" &
done
for pcap in "$data"/ctu13/*.pcap; do
	name=$(basename "$pcap" .pcap | sed 's/botnet-capture-[0-9]*-//')
	run "ctu13-$name" "ctu13/$(basename "$pcap")" /eval/site-ctu13.zeek
done
wait
