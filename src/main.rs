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
use crate::packet::{HftWindow, QuotePacketView, print_quote, QUOTE_PACKET_SIZE};
use crate::parser::CustomPcapReader;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short)]
    r: bool,

    #[arg(short, long)]
    file: String,

    #[arg(short, long)]
    bench: bool,
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
    let mut scratchpad = Vec::with_capacity(512);
    let mut itoa_buf = itoa::Buffer::new();

    for (hdr, packet) in custom_reader {
        if packet.len() < 42 + QUOTE_PACKET_SIZE { continue; }
        
        // Check port manually (bytes 36-37 are UDP Dest Port)
        let d_port = u16::from_be_bytes([packet[36], packet[37]]);
        if d_port != 15515 && d_port != 15516 { continue; }

        let payload = &packet[42..];

        let Some(qp_view) = QuotePacketView::try_new(&payload, d_port) else {
            continue;
        };

        let accept_time_ns = qp_view.accept_time_ns();
        let ts_sec = hdr.ts_sec as u64;
        let ts_usec = hdr.ts_usec as u64;

        let seconds_today = (ts_sec + tz_offset_secs) % 86400;
        let pkt_micros_of_day = seconds_today * 1_000_000 + ts_usec;

        if args.r {
            hft_window.push(qp_view, pkt_micros_of_day, accept_time_ns, &mut out, &mut scratchpad, &mut itoa_buf, args.bench);
        } else {
            let _ = print_quote(&mut out, &qp_view, pkt_micros_of_day, accept_time_ns, &mut scratchpad, &mut itoa_buf, args.bench);
        }
    }

    hft_window.drain_all(&mut out, &mut scratchpad, &mut itoa_buf, args.bench);

    out.flush().unwrap(); // Ensure everything is written to stdout

    Ok(())
}
