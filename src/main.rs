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
                        println!("Issue Code: {:?}", quote_packet.issue_code());
                        println!("Accept Time: {:?}", quote_packet.accept_time());
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
