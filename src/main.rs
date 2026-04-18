mod error;
mod packet;

use anyhow::Result;
use clap::Parser;
use etherparse::{SlicedPacket, TransportSlice};

use std::path::Path;

use memmap2::Mmap;
use pcap_file::pcap::PcapReader;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;

use crate::error::CustomError;
use crate::packet::{Quote, QuotePacketView};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short)]
    r: bool,
}

fn print_quote(quote: Quote) {
    let (bid_price1, bid_qty1) = quote.quote.bid(0);
    let (bid_price2, bid_qty2) = quote.quote.bid(1);
    let (bid_price3, bid_qty3) = quote.quote.bid(2);
    let (bid_price4, bid_qty4) = quote.quote.bid(3);
    let (bid_price5, bid_qty5) = quote.quote.bid(4);
    // println!("Bid 1: {:?}@{:?}", bid_price1, bid_qty1);
    // println!("Bid 2: {:?}@{:?}", bid_price2, bid_qty2);
    // println!("Bid 3: {:?}@{:?}", bid_price3, bid_qty3);
    // println!("Bid 4: {:?}@{:?}", bid_price4, bid_qty4);
    // println!("Bid 5: {:?}@{:?}", bid_price5, bid_qty5);
    // println!("---");

    let (ask_price1, ask_qty1) = quote.quote.ask(0);
    let (ask_price2, ask_qty2) = quote.quote.ask(1);
    let (ask_price3, ask_qty3) = quote.quote.ask(2);
    let (ask_price4, ask_qty4) = quote.quote.ask(3);
    let (ask_price5, ask_qty5) = quote.quote.ask(4);
    // println!("Ask 1: {:?}@{:?}", ask_price1, ask_qty1);
    // println!("Ask 2: {:?}@{:?}", ask_price2, ask_qty2);
    // println!("Ask 3: {:?}@{:?}", ask_price3, ask_qty3);
    // println!("Ask 4: {:?}@{:?}", ask_price4, ask_qty4);
    // println!("Ask 5: {:?}@{:?}", ask_price5, ask_qty5);
    println!(
        "{:?} {:?} {:?} {:?}@{:?} {:?}@{:?} {:?}@{:?} {:?}@{:?} {:?}@{:?} {:?}@{:?} {:?}@{:?} {:?}@{:?} {:?}@{:?} {:?}@{:?}",
        quote.pkt_time,
        quote.accept_time,
        quote.quote.issue_code(),
        bid_qty5,
        bid_price5,
        bid_qty4,
        bid_price4,
        bid_qty3,
        bid_price3,
        bid_qty2,
        bid_price2,
        bid_qty1,
        bid_price1,
        ask_qty5,
        ask_price5,
        ask_qty4,
        ask_price4,
        ask_qty3,
        ask_price3,
        ask_qty2,
        ask_price2,
        ask_qty1,
        ask_price1
    );
    println!("---");
}

fn main() -> Result<(), CustomError> {
    let args = Args::parse();

    if args.r {
        println!("Enabled");
    } else {
        println!("Disabled");
    }

    let file = File::open("./data/mdf-kospi200.20110216-0.pcap")
        .map_err(|e| CustomError::ParseError(format!("Error: {:?}", e)))?;
    let mmap = unsafe {
        Mmap::map(&file).map_err(|e| CustomError::ParseError(format!("Error: {:?}", e)))?
    };
    let data = &mmap[..];

    let mut cap = PcapReader::new(data)
        .map_err(|e| CustomError::ParseError(format!("Pcap Header Error: {:?}", e)))?;

    let mut heap = BinaryHeap::new();
    let window_micros: u64 = 3_000_000; // 3 seconds

    // let s_idx = start_bytes.len();
    while let Some(Ok(packet)) = cap.next_packet() {
        // let ts_sec = pkt.header.ts.tv_sec;
        // let ts_usec = pkt.header.ts.tv_usec;

        // let packet = pkt.unwrap();

        let raw_payload = unsafe {
            // This is safe because we know 'packet.data' is a sub-slice of 'mmap'
            // and 'mmap' outlives the heap.
            std::mem::transmute::<&[u8], &'static [u8]>(packet.data.as_ref())
        };

        match SlicedPacket::from_ethernet(raw_payload) {
            Ok(value) => {
                match value.transport {
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        let payload = udp.payload();
                        let d_port = udp.destination_port();
                        // Check for the start byte which we are interested in.

                        let Some(quote_packet) = QuotePacketView::try_new(&payload) else {
                            continue;
                        };
                        
                        let ts_sec = packet.timestamp.as_secs();
                        let ts_usec = packet.timestamp.subsec_micros() as u64;

                        let tz_offset_secs = 9 * 3600; // Expecting the packet was captured in a timezone which is KST. 9 hours ahead )
                        let seconds_today = (ts_sec + tz_offset_secs) % 86400;

                        let normalized_pkt_micros = (seconds_today as u64 * 1_000_000) + (ts_usec as u64);

                        let accept_time = quote_packet.accept_time();

                        let item = Quote {
                            pkt_time: ts_sec,
                            accept_time,
                            quote: quote_packet,
                        };

                        if args.r {
                            heap.push(item);

                            while let Some(oldest) = heap.peek() {
                                if normalized_pkt_micros > oldest.accept_time + window_micros {
                                    let curr_quote = heap.pop().unwrap();
                                    print_quote(curr_quote);
                                } else {
                                    break; // from heap peek
                                }
                            }
                        } else {
                            print_quote(item);
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => return Err(CustomError::ParseError(format!("Error {:?}", e))),
        }
    }

    while let Some(remaining_quote) = heap.pop() {
        print_quote(remaining_quote);
    }

    Ok(())
}
