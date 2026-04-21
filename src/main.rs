mod error;
mod packet;
mod parser;

use anyhow::Result;
use clap::Parser;
use etherparse::{SlicedPacket, TransportSlice};
use memmap2::Mmap;
use std::{
    fs::File,
    io::{self, BufWriter, Write},
};

use crate::error::CustomError;
use crate::packet::{HftWindow, QuotePacketView, print_quote};
use crate::parser::CustomPcapReader;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short)]
    r: bool,

    #[arg(short, long)]
    file: String,
}

fn main() -> Result<(), CustomError> {
    let args = Args::parse();

    if args.r {
        println!("Enabled");
    } else {
        println!("Disabled");
    }

    let file =
        File::open(&args.file).map_err(|e| CustomError::ParseError(format!("Error: {:?}", e)))?;
    let mmap = unsafe {
        Mmap::map(&file)
            .map_err(|e| CustomError::InvalidPacketStructure(format!("Error: {:?}", e)))?
    };

    let custom_reader = CustomPcapReader::new(&mmap);
    let mut out = BufWriter::with_capacity(1 << 20, io::stdout());
    let mut hft_window = HftWindow::new();

    let tz_offset_secs = 9 * 3600;

    for (hdr, packet) in custom_reader {
        let Ok(value) = SlicedPacket::from_ethernet(packet) else {
            continue;
        };

        let Some(TransportSlice::Udp(udp)) = value.transport else {
            continue;
        };

        let payload = udp.payload();
        let d_port = udp.destination_port();

        let Some(qp_view) = QuotePacketView::try_new(&payload, d_port) else {
            continue;
        };

        let accept_time = qp_view.accept_time();
        let ts_sec = hdr.ts_sec as u64;
        let ts_usec = hdr.ts_usec as u64;

        let seconds_today = (ts_sec + tz_offset_secs) % 86400;
        let pkt_micros_of_day = seconds_today * 1_000_000 + ts_usec;

        if args.r {
            hft_window.push(qp_view, pkt_micros_of_day, accept_time, &mut out);
        } else {
            let _ = print_quote(&mut out, &qp_view, pkt_micros_of_day, accept_time);
        }
    }

    hft_window.drain_all(&mut out);

    out.flush().unwrap(); // Ensure everything is written to stdout

    Ok(())
}
