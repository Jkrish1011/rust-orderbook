mod error;
mod packet;

use anyhow::Result;
use clap::Parser;
use etherparse::{SlicedPacket, TransportSlice};
use pcap::Capture;
use std::path::Path;

use crate::error::CustomError;
use crate::packet::QuotePacketView;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short)]
    r: bool,
}

fn main() -> Result<(), CustomError> {
    let args = Args::parse();

    if args.r {
        println!("Enabled");
    } else {
        println!("Disabled");
    }

    let mut cap = Capture::from_file(Path::new("./data/mdf-kospi200.20110216-0.pcap"))
        .map_err(|_| CustomError::ParseError("Couln't open the file".to_string()))?;
    // let s_idx = start_bytes.len();
    while let Ok(packet) = cap.next_packet() {
        let ts_sec = packet.header.ts.tv_sec;
        let ts_usec = packet.header.ts.tv_usec;

        match SlicedPacket::from_ethernet(&packet.data) {    
            Ok(value) => {
                match value.transport {
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        let payload = udp.payload();
                        let d_port = udp.destination_port();
                        // Check for the start byte which we are interested in.

                        let Some(quote_packet) = QuotePacketView::try_new(&payload) else {
                            continue;
                        };
                        // println!("{}.{:06}", ts_sec, ts_usec);
                        let tz_offset_secs = 9 * 3600; // Expecting the packet was captured in a timezone which is KST. 9 hours ahead )
                        let seconds_today = (ts_sec + tz_offset_secs) % 86400; 

                        let packet_total_micros = (seconds_today as u64 * 1_000_000) + (ts_usec as u64);
                        println!("Packet Time: {}", packet_total_micros);
                        println!("Issue Code: {:?}", quote_packet.issue_code());
                        println!("Accept Time: {:?}", quote_packet.accept_time());
                        let (bid_price1, bid_qty1) = quote_packet.bid(0);
                        let (bid_price2, bid_qty2) = quote_packet.bid(1);
                        let (bid_price3, bid_qty3) = quote_packet.bid(2);
                        let (bid_price4, bid_qty4) = quote_packet.bid(3);
                        let (bid_price5, bid_qty5) = quote_packet.bid(4);
                        println!("Bid 1: {:?}@{:?}", bid_price1, bid_qty1);
                        println!("Bid 2: {:?}@{:?}", bid_price2, bid_qty2);
                        println!("Bid 3: {:?}@{:?}", bid_price3, bid_qty3);
                        println!("Bid 4: {:?}@{:?}", bid_price4, bid_qty4);
                        println!("Bid 5: {:?}@{:?}", bid_price5, bid_qty5);
                        println!("---");

                        let (ask_price1, ask_qty1) = quote_packet.ask(0);
                        let (ask_price2, ask_qty2) = quote_packet.ask(1);
                        let (ask_price3, ask_qty3) = quote_packet.ask(2);
                        let (ask_price4, ask_qty4) = quote_packet.ask(3);
                        let (ask_price5, ask_qty5) = quote_packet.ask(4);
                        println!("Ask 1: {:?}@{:?}", ask_price1, ask_qty1);
                        println!("Ask 2: {:?}@{:?}", ask_price2, ask_qty2);
                        println!("Ask 3: {:?}@{:?}", ask_price3, ask_qty3);
                        println!("Ask 4: {:?}@{:?}", ask_price4, ask_qty4);
                        println!("Ask 5: {:?}@{:?}", ask_price5, ask_qty5);
                        println!("---");
                        // if payload.starts_with(QUOTE_PREFIX) && (d_port == 15515 || d_port == 15516) {

                        //     let data_type = &payload[..2];
                        //     println!("Data type is : {:?}", std::str::from_utf8(data_type));

                        //     // println!("link: {:?}", value.link);

                        //     // println!("link_exts: {:?}", value.link_exts); // contains vlan & macsec
                        //     // println!("net: {:?}", value.net); // contains ip & arp

                        // }
                    }
                    _ => {}
                }
            }
            Err(e) => return Err(CustomError::ParseError(format!("Error {:?}", e))),
        }
    }
    Ok(())
}
