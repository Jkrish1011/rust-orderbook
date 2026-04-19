mod error;
mod packet;

use anyhow::Result;
use clap::Parser;
use crossbeam::queue::ArrayQueue;
use etherparse::{SlicedPacket, TransportSlice};
use memmap2::Mmap;
use pcap_file::pcap::PcapReader;
use std::{
    collections::BinaryHeap,
    fs::File,
    io::{self, BufWriter, Write},
    sync::Arc,
    thread,
    time::Instant,
};

use crate::error::CustomError;
use crate::packet::{QUOTE_PACKET_SIZE, QuoteMeta, QuotePacketView};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short)]
    r: bool,
}

#[inline(never)]
fn print_quote<W: Write>(out: &mut W, quote: &QuotePacketView, pkt_time: u64, accept_time: u64) -> io::Result<()> {
    let (bid_price1, bid_qty1) = quote.bid(0);
    let (bid_price2, bid_qty2) = quote.bid(1);
    let (bid_price3, bid_qty3) = quote.bid(2);
    let (bid_price4, bid_qty4) = quote.bid(3);
    let (bid_price5, bid_qty5) = quote.bid(4);
    // println!("Bid 1: {:?}@{:?}", bid_price1, bid_qty1);
    // println!("Bid 2: {:?}@{:?}", bid_price2, bid_qty2);
    // println!("Bid 3: {:?}@{:?}", bid_price3, bid_qty3);
    // println!("Bid 4: {:?}@{:?}", bid_price4, bid_qty4);
    // println!("Bid 5: {:?}@{:?}", bid_price5, bid_qty5);
    // println!("---");

    let (ask_price1, ask_qty1) = quote.ask(0);
    let (ask_price2, ask_qty2) = quote.ask(1);
    let (ask_price3, ask_qty3) = quote.ask(2);
    let (ask_price4, ask_qty4) = quote.ask(3);
    let (ask_price5, ask_qty5) = quote.ask(4);
    // println!("Ask 1: {:?}@{:?}", ask_price1, ask_qty1);
    // println!("Ask 2: {:?}@{:?}", ask_price2, ask_qty2);
    // println!("Ask 3: {:?}@{:?}", ask_price3, ask_qty3);
    // println!("Ask 4: {:?}@{:?}", ask_price4, ask_qty4);
    // println!("Ask 5: {:?}@{:?}", ask_price5, ask_qty5);
    writeln!(
        out,
        "{} {} {} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{}",
        pkt_time,
        accept_time,
        quote.issue_code(),
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
    )?;

    Ok(())
}

fn main() -> Result<(), CustomError> {
    let start = Instant::now();
    let args = Args::parse();

    let queue = Arc::new(ArrayQueue::<QuoteMeta>::new(1 << 16));
    // Get list of available core IDs
    let core_ids = core_affinity::get_core_ids().unwrap();
    let core_reader = core_ids[0];
    let core_writer = core_ids[1];

    if args.r {
        println!("Enabled");
    } else {
        println!("Disabled");
    }

    let file = File::open("./data/mdf-kospi200.20110216-0.pcap")
        .map_err(|e| CustomError::ParseError(format!("Error: {:?}", e)))?;
    let mmap = unsafe {
        Mmap::map(&file)
            .map_err(|e| CustomError::InvalidPacketStructure(format!("Error: {:?}", e)))?
    };
    let mmap = Arc::new(mmap);

    let mmap_reader = mmap.clone();
    let queue_reader = queue.clone();

    let reader = thread::spawn(move || {
        if core_affinity::set_for_current(core_reader) {
            println!("Thread pinned to core {:?}", core_reader);
        } else {
            eprintln!("Failed to pin thread");
        }

        let data: &[u8] = &mmap_reader[..];

        let mut cap = PcapReader::new(data).unwrap();

        let base_ptr = mmap_reader.as_ptr() as usize;

        while let Some(Ok(packet)) = cap.next_packet() {
            let raw_payload = packet.data.as_ref();

            let Ok(value) = SlicedPacket::from_ethernet(raw_payload) else {
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
            let ts_sec = packet.timestamp.as_secs();
            let ts_usec = packet.timestamp.subsec_micros() as u64;

            let tz_offset_secs = 9 * 3600;
            let seconds_today = (ts_sec + tz_offset_secs) % 86400;

            let normalized_pkt_micros = (seconds_today as u64 * 1_000_000) + ts_usec;

            let offset = payload.as_ptr() as usize - base_ptr;

            let meta = QuoteMeta {
                pkt_time: normalized_pkt_micros,
                accept_time,
                offset,
            };

            while queue_reader.push(meta).is_err() {
                // to make the busy-wait less harmful
                std::hint::spin_loop();
            }
        }
    });

    let mmap_writer = mmap.clone();
    let queue_writer = queue.clone();

    let writer = thread::spawn(move || {
        if core_affinity::set_for_current(core_writer) {
            println!("Thread pinned to core {:?}", core_writer);
        } else {
            eprintln!("Failed to pin thread");
        }

        let stdout = io::stdout();
        let lock = stdout.lock();

        let mut out = BufWriter::with_capacity(1 << 20, lock);
        let mut heap = BinaryHeap::new();
        let window_micros = 3_000_000;

        loop {
            if let Some(meta) = queue_writer.pop() {
                if args.r {
                    heap.push(meta);

                    while let Some(oldest) = heap.peek() {
                        if meta.pkt_time > oldest.accept_time + window_micros {
                            let q = heap.pop().unwrap();
                            let slice = &mmap_writer[q.offset..q.offset + QUOTE_PACKET_SIZE];
                            let view = QuotePacketView::new_unchecked(slice).unwrap();
                            let _ = print_quote(&mut out, &view, q.pkt_time, q.accept_time);
                        } else {
                            break; // from heap peek
                        }
                    }
                } else {
                    let slice = &mmap_writer[meta.offset..meta.offset + QUOTE_PACKET_SIZE];
                    let view = QuotePacketView::new_unchecked(slice).unwrap();
                    let _ = print_quote(&mut out, &view, meta.pkt_time, meta.accept_time);
                }
            } else {
                std::hint::spin_loop();
            }
        }
    });

    reader.join().unwrap();
    writer.join().unwrap();

    let elapsed = start.elapsed();
    println!("Total Time Elapsed: {:.3} s", elapsed.as_secs_f64());

    Ok(())
}
