mod error;

use pcap::{Capture};
use etherparse::{SlicedPacket, TransportSlice};
use std::path::Path;
use anyhow::{Result};
use clap::Parser;

use crate::error::CustomError;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short)]
    r: bool
}


fn main() -> Result<(), CustomError> {
    let args = Args::parse();

    if args.r {
        println!("Enabled");
    } else{
        println!("Disabled");
    }
    

    let mut cap = Capture::from_file(Path::new("./data/mdf-kospi200.20110216-0.pcap")).map_err(|_| CustomError::ParseError("Couln't open the file".to_string()))?;
    
    while let Ok(packet) = cap.next_packet() {
        match SlicedPacket::from_ethernet(&packet.data) {
            Ok(value) => {
               
                match value.transport.clone() {
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        let payload = udp.payload();
                        let d_port = udp.destination_port();
                        // Check for the start byte which we are interested in.

                        if payload.starts_with(b"B6034") && (d_port == 15515 || d_port == 15516) {
                            println!("paylod: {:?}", payload);
                            println!("d_port: {:?}", d_port);
                            // println!("link: {:?}", value.link);
                            
                            // println!("link_exts: {:?}", value.link_exts); // contains vlan & macsec
                            // println!("net: {:?}", value.net); // contains ip & arp
                            
                        }
                        
                    }
                    _ => {}
                }
            }
            Err(e) => return Err(CustomError::ParseError(format!("Error {:?}", e))),
        }
    }
    Ok(())
}
