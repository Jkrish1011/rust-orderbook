mod error;
mod packet;
mod parser;

use anyhow::Result;
use chrono::{FixedOffset, NaiveDateTime, TimeZone, Timelike, Utc};
use clap::Parser;
use crossbeam::queue::ArrayQueue;
use etherparse::{SlicedPacket, TransportSlice};
use memmap2::Mmap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::BinaryHeap,
    fs::File,
    io::{self, BufWriter, Write},
    sync::Arc,
    thread,
    time::Instant,
};

use crate::error::CustomError;
use crate::packet::{HftWindow, QUOTE_PACKET_SIZE, QuoteMeta, QuotePacketView, print_quote};
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
    let start = Instant::now();
    let args = Args::parse();

    let queue = Arc::new(ArrayQueue::<QuoteMeta>::new(1 << 20));
    let done = Arc::new(AtomicBool::new(false));
    // Get list of available core IDs
    let core_ids = core_affinity::get_core_ids().unwrap();
    let core_reader = core_ids[0];
    let core_writer = core_ids[1];

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
    let mmap = Arc::new(mmap);

    let mmap_reader = mmap.clone();
    let queue_reader = queue.clone();
    let done_reader = done.clone();

    let reader = thread::spawn(move || {
        if core_affinity::set_for_current(core_reader) {
            println!("Thread pinned to core {:?}", core_reader);
        } else {
            eprintln!("Failed to pin thread");
        }

        let data: &[u8] = &mmap_reader[..];

        // let mut cap = PcapReader::new(data).unwrap();
        let mut custom_reader = CustomPcapReader::new(&mmap_reader);

        let base_ptr = mmap_reader.as_ptr() as usize;

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
            let packet_epoch = hdr.ts_sec as i64;
            let packet_sub_us = hdr.ts_usec as u32; // or hdr.ts_nsec for nsec case

            let kst = FixedOffset::east_opt(9 * 3600).unwrap();
            let dt_utc = NaiveDateTime::from_timestamp_opt(packet_epoch, 0).unwrap();
            let dt_kst = chrono::DateTime::<Utc>::from_utc(dt_utc, Utc).with_timezone(&kst);

            // microseconds since midnight in KST
            let pkt_micros_of_day =
                dt_kst.time().num_seconds_from_midnight() as u64 * 1_000_000 + packet_sub_us as u64;

            let offset = payload.as_ptr() as usize - base_ptr;

            let meta = QuoteMeta {
                pkt_time: pkt_micros_of_day,
                accept_time,
                offset,
            };

            while queue_reader.push(meta).is_err() {
                // to make the busy-wait less harmful
                std::hint::spin_loop();
            }
        }

        done_reader.store(true, Ordering::Release);
    });

    let mmap_writer = mmap.clone();
    let queue_writer = queue.clone();
    let done_writer = done.clone();

    let writer = thread::spawn(move || {
        if core_affinity::set_for_current(core_writer) {
            println!("Thread pinned to core {:?}", core_writer);
        } else {
            eprintln!("Failed to pin thread");
        }

        let mut out = BufWriter::with_capacity(1 << 20, io::stdout());
        let mut hft_window = HftWindow::new();

        let window_micros = 3_000_000;
        loop {
            while let Some(meta) = queue_writer.pop() {
                if args.r {
                    let slice = &mmap_writer[meta.offset..meta.offset + QUOTE_PACKET_SIZE];
                    let view = QuotePacketView::new_unchecked(slice).unwrap();

                    hft_window.push(view, meta.pkt_time, meta.accept_time, &mut out);
                } else {
                    let slice = &mmap_writer[meta.offset..meta.offset + QUOTE_PACKET_SIZE];
                    let view = QuotePacketView::new_unchecked(slice).unwrap();
                    let _ = print_quote(&mut out, &view, meta.pkt_time, meta.accept_time);
                }
            }

            if done_writer.load(Ordering::Acquire) {
                while let Some(meta) = queue_writer.pop() {
                    if args.r {
                        let slice = &mmap_writer[meta.offset..meta.offset + QUOTE_PACKET_SIZE];
                        let view = QuotePacketView::new_unchecked(slice).unwrap();

                        hft_window.push(view, meta.pkt_time, meta.accept_time, &mut out);
                    } else {
                        let slice = &mmap_writer[meta.offset..meta.offset + QUOTE_PACKET_SIZE];
                        let view = QuotePacketView::new_unchecked(slice).unwrap();
                        let _ = print_quote(&mut out, &view, meta.pkt_time, meta.accept_time);
                    }
                }
                break;
            } else {
                std::hint::spin_loop();
            }
        }

        hft_window.drain_all(&mut out);

        out.flush().unwrap(); // Ensure everything is written to stdout
    });

    reader.join().unwrap();
    writer.join().unwrap();

    let elapsed = start.elapsed();
    println!("Total Time Elapsed: {:.3} s", elapsed.as_secs_f64());

    Ok(())
}
