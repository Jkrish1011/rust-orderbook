mod error;

use pcap::{Capture};
use etherparse::{SlicedPacket, TransportSlice};
use std::path::Path;
use anyhow::{Result};
use clap;

use crate::error::CustomError;


fn main() -> Result<(), CustomError> {
    let mut cap = Capture::from_file(Path::new("./data/mdf-kospi200.20110216-0.pcap")).map_err(|_| CustomError::ParseError("Couln't open the file".to_string()))?;
    
    while let Ok(packet) = cap.next_packet() {
        match SlicedPacket::from_ethernet(&packet.data) {
            Ok(value) => {
                // println!("link: {:?}", value.link);
                // println!("link_exts: {:?}", value.link_exts); // contains vlan & macsec
                // println!("net: {:?}", value.net); // contains ip & arp
                // println!("transport: {:?}", value.transport);

                match value.transport {
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        let payload = udp.payload();
                        // Check for the start byte which we are interested in.
                        if payload.starts_with(b"B6034") {
                            println!("paylod: {:?}", String::from_utf8_lossy(payload));
                        }
                        
                    }
                    _ => {}
                }
            }
            Err(e) => println!("Error {:?}", e),
        }
    }
    Ok(())
}
