# Rust Orderbook

A command-line tool, written in Rust, that extracts and prints quote messages from a pcap capture of a market data feed. When given the -r flag it reorders output by the exchange's quote accept time.

## Features
- Stream-oriented: processes pcap without loading the whole file into memory.
- Reordering mode (-r): outputs messages ordered by quote accept time using a bounded-time window (±3s) to limit memory usage.
- Filters UDP payloads for packets starting with ASCII B6034 and parses quote fields according to the provided specification.

## Reordering behavior and performance
- -r reorders by quote accept time, assuming the difference between accept time and pcap packet time is <= 3 seconds.
- Streaming, bounded-memory approach:

    - Maintain an in-memory buffer keyed by accept time.
    - Push parsed messages into the buffer as they are read.
    - Track the maximum observed packet timestamp and flush buffered messages whose accept time is older than (max_packet_time - 3s).

- Designed to work efficiently on files larger than available RAM: minimal allocations, byte-slice parsing, and streaming pcap reading.