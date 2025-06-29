#!/bin/bash

PCAP_DIR="./pcap_repository/"
SURICATA_CONF="./suricata.yaml"
SURICATA_RULES="./suricata.rules"
LOG_DIR="./logs/manual_runs/"

mkdir -p "$LOG_DIR"

for pcap in "$PCAP_DIR"/*.pcapng; do
    [ -e "$pcap" ] || continue
    BASENAME=$(basename "$pcap" .pcapng)
    OUTDIR="$LOG_DIR/$BASENAME"
    mkdir -p "$OUTDIR"
    # suricata -c "$SURICATA_CONF" -r "$pcap" -S "$SURICATA_RULES" -l "$OUTDIR" -k none
    suricata -c "$SURICATA_CONF" -r "$pcap" -l "$OUTDIR" -k none
    echo "Processed $pcap -> $OUTDIR"
done
