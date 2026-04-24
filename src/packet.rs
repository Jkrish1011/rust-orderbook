use std::{
    io::{self, Write},
};

pub const QUOTE_PACKET_SIZE: usize = 215;
pub const QUOTE_PREFIX: &[u8; 5] = b"B6034";
pub const ISSUE_CODE_META: &[usize; 2] = &[5, 12]; // OFFSET_VALUE, LENGTH
pub const ACCEPT_TIME_META: &[usize; 2] = &[206, 8];
pub const BID_FIRST_PRICE_META: &[usize; 2] = &[29, 5];
pub const BID_FIRST_QTY_META: &[usize; 2] = &[34, 7];
pub const ASK_FIRST_PRICE_META: &[usize; 2] = &[96, 5];
pub const ASK_FIRST_QTY_META: &[usize; 2] = &[101, 7];
pub const LEVEL_STRIDE: usize = 12;
pub const END_OF_PACKET: usize = 214;
const NUM_BUCKETS: usize = 512;
const MAX_NO_PACKETS: usize = 1024;
const TOTAL_CAPACITY: usize = NUM_BUCKETS * MAX_NO_PACKETS;
const MASK: u64 = 511;
const WINDOW_LIMIT_CS: u64 = 300; // 3 seconds

pub struct HftWindow<'a> {
    buckets: Vec<(QuotePacketView<'a>, u64, u64)>,
    counts: [usize; NUM_BUCKETS],
    max_time_seen: u64,
}

impl<'a> HftWindow<'a> {
    pub fn new() -> Self {
        
        let mut pool = Vec::with_capacity(TOTAL_CAPACITY);

        // by using unsafe we tell the OS to not zeroing this
        unsafe {
            pool.set_len(TOTAL_CAPACITY);
        }

        Self {
            buckets: pool,
            counts: [0; NUM_BUCKETS],
            max_time_seen: 0,
        }
    }

    #[inline(always)]
    pub fn push<W: std::io::Write>(
        &mut self,
        packet: QuotePacketView<'a>,
        pkt_time: u64,
        accept_time: u64,
        out: &mut W,
        scratchpad: &mut Vec<u8>
    ) {
        let pkt_time_cs = pkt_time / 10_000;

        // Advance time using the centisecond time
        if pkt_time_cs > self.max_time_seen {
            self.advance_time(pkt_time_cs, out, scratchpad);
        }

        // Drop the new packet into its bucket
        let index = (pkt_time_cs & MASK) as usize;
        let curr_count = self.counts[index];

        if curr_count < MAX_NO_PACKETS {
            // (index * MAX_NO_PACKETS) + curr_count
            let flat_index = (index * MAX_NO_PACKETS) + curr_count;
            
            unsafe {
                *self.buckets.get_unchecked_mut(flat_index) = (packet, pkt_time, accept_time);
            }
            self.counts[index] += 1;
        }
    }

    #[inline(always)]
    fn advance_time<W: std::io::Write>(&mut self, p_time: u64, out: &mut W, scratchpad: &mut Vec<u8>) {

        // If the gap between the new packet and the oldest allowed packet
        // is > 300cs, we must drain and print the oldest buckets.

        let oldest_allowed = p_time.saturating_sub(WINDOW_LIMIT_CS);
        let mut drain_time = self.max_time_seen.saturating_sub(WINDOW_LIMIT_CS);

        while drain_time < oldest_allowed {
            let idx = (drain_time & MASK) as usize;
            let count = self.counts[idx];
            let base_idx = MAX_NO_PACKETS * idx;

            for i in 0..count {
                let (pkt, p_time, a_time) = unsafe {
                    self.buckets.get_unchecked(base_idx + i)
                };
                let _ = print_quote(out, pkt, *p_time, *a_time, scratchpad);
            }
            
            // CLEAR the bucket for future use (keeps capacity, sets length to 0)
            self.counts[idx] = 0;

            drain_time += 1;
        }

        self.max_time_seen = p_time;
    }

    #[inline(always)]
    pub fn drain_all<W: std::io::Write>(&mut self, out: &mut W, scratchpad: &mut Vec<u8>) {
        let start_time = self.max_time_seen.saturating_sub(WINDOW_LIMIT_CS);

        // Print everything in this bucket
        for t in start_time..=self.max_time_seen {
            let idx = (t & MASK) as usize;
            let count = self.counts[idx];
            let base_idx = MAX_NO_PACKETS * idx;

            for i in 0..count {
                let (pkt, p_time, a_time)  = unsafe {
                    self.buckets.get_unchecked(base_idx + i)
                };
                let _ = print_quote(out, pkt, *p_time, *a_time, scratchpad);
            }
            self.counts[idx]= 0;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuotePacketView<'a> {
    raw: &'a [u8],
}

impl<'a> QuotePacketView<'a> {
    #[inline(always)]
    pub fn try_new(raw: &'a [u8], port: u16) -> Option<Self> {
        if raw.len() == QUOTE_PACKET_SIZE
            && &raw[0..5] == QUOTE_PREFIX
            && raw[END_OF_PACKET] == 0xFF
            && (port == 15515 || port == 15516)
        {
            Some(Self { raw })
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn new_unchecked(raw: &'a [u8]) -> Option<Self> {
        Some(Self { raw })
    }

    #[inline(always)]
    pub fn parse_ascii_to_u32(bytes: &[u8]) -> u32 {
        let mut acc: u32 = 0;
        // bitwise operations are 1 cpu cycle
        for &b in bytes {
            // (b & 0x0F) converts the ASCII byte to an integer from 0-9
            // acc * 10 shifts the current total to the left by one base-10 digit
            acc = acc * 10 + (b & 0x0F) as u32;
        }

        acc
    }

    #[inline(always)]
    pub fn issue_code(&self) -> &'a str {
        std::str::from_utf8(
            &self.raw[ISSUE_CODE_META[0]..(ISSUE_CODE_META[0] + ISSUE_CODE_META[1])],
        )
        .unwrap()
    }

     #[inline(always)]
    pub fn issue_code_raw(&self) -> &'a [u8] {
        &self.raw[ISSUE_CODE_META[0]..(ISSUE_CODE_META[0] + ISSUE_CODE_META[1])]
    }

    #[inline(always)]
    pub fn accept_time(&self) -> u64 {
        let time_ref = unsafe {
            self.raw
                .get_unchecked(ACCEPT_TIME_META[0]..(ACCEPT_TIME_META[0] + ACCEPT_TIME_META[1]))
        };

        let hh = ((time_ref[0] & 0x0F) as u64) * 10 + ((time_ref[1] & 0x0F) as u64);
        let mm = ((time_ref[2] & 0x0F) as u64) * 10 + ((time_ref[3] & 0x0F) as u64);
        let ss = ((time_ref[4] & 0x0F) as u64) * 10 + ((time_ref[5] & 0x0F) as u64);
        let uu = ((time_ref[6] & 0x0F) as u64) * 10 + ((time_ref[7] & 0x0F) as u64);

        (hh * 3600 + mm * 60 + ss) * 1_000_000 + (uu * 10_000)
    }

    #[inline(always)]
    pub fn accept_time_raw(&self) -> &'a [u8] {
        let time_ref = unsafe {
            self.raw.get_unchecked(ACCEPT_TIME_META[0]..(ACCEPT_TIME_META[0] + ACCEPT_TIME_META[1]))
        };

        time_ref
    }

    #[inline(always)]
    pub fn bid_raw(&self, level: usize) -> (&'a [u8], &'a [u8]) {
        let base = level * LEVEL_STRIDE;
        let price_start = BID_FIRST_PRICE_META[0] + base;
        let qty_start = BID_FIRST_QTY_META[0] + base;

        (
            &self.raw[price_start..(price_start + BID_FIRST_PRICE_META[1])],
            &self.raw[qty_start..(qty_start + BID_FIRST_QTY_META[1])]
        )
    }

    #[inline(always)]
    pub fn bid(&self, level: usize) -> (u32, u32) {
        let base = level * LEVEL_STRIDE;
        let price_start = BID_FIRST_PRICE_META[0] + base;
        let qty_start = BID_FIRST_QTY_META[0] + base;

        (
            Self::parse_ascii_to_u32(
                &self.raw[price_start..(price_start + BID_FIRST_PRICE_META[1])],
            ),
            Self::parse_ascii_to_u32(&self.raw[qty_start..(qty_start + BID_FIRST_QTY_META[1])]),
        )
    }


    #[inline(always)]
    pub fn ask_raw(&self, level: usize) -> (&'a [u8], &'a [u8]) {
        let base = level * LEVEL_STRIDE;
        let price_start = ASK_FIRST_PRICE_META[0] + base;
        let qty_start = ASK_FIRST_QTY_META[0] + base;

        (
            &self.raw[price_start..(price_start + ASK_FIRST_PRICE_META[1])],
            &self.raw[qty_start..(qty_start + ASK_FIRST_QTY_META[1])]
        )
    }

    #[inline(always)]
    pub fn ask(&self, level: usize) -> (u32, u32) {
        let base = level * LEVEL_STRIDE;
        let price_start = ASK_FIRST_PRICE_META[0] + base;
        let qty_start = ASK_FIRST_QTY_META[0] + base;

        (
            Self::parse_ascii_to_u32(
                &self.raw[price_start..(price_start + ASK_FIRST_PRICE_META[1])],
            ),
            Self::parse_ascii_to_u32(&self.raw[qty_start..(qty_start + ASK_FIRST_QTY_META[1])]),
        )
    }
}


pub fn print_quote<W: Write>(
    out: &mut W,
    quote: &QuotePacketView,
    pkt_time: u64,
    accept_time: u64,
    scratchpad: &mut Vec<u8>
) -> io::Result<()> {
    scratchpad.clear();

    let mut itoa_buf = itoa::Buffer::new();
    // 1. Add pkt_time and accept_time
    scratchpad.extend_from_slice(itoa_buf.format(pkt_time).as_bytes());
    scratchpad.push(b' ');
    scratchpad.extend_from_slice(itoa_buf.format(accept_time).as_bytes());
    scratchpad.push(b' ');

    // 2. Add issue_code
    scratchpad.extend_from_slice(quote.issue_code_raw());

    // 3. Add Bids (Level 5 down to 1: indices 4, 3, 2, 1, 0)
    for i in (0..5).rev() {
        let (price, qty) = quote.bid(i);
        scratchpad.push(b' ');
        scratchpad.extend_from_slice(itoa_buf.format(qty).as_bytes());
        scratchpad.push(b'@');
        scratchpad.extend_from_slice(itoa_buf.format(price).as_bytes());
    }

    // 4. Add Asks (Level 5 down to 1: indices 4, 3, 2, 1, 0)
    for i in (0..5).rev() {
        let (price, qty) = quote.ask(i);
        scratchpad.push(b' ');
        scratchpad.extend_from_slice(itoa_buf.format(qty).as_bytes());
        scratchpad.push(b'@');
        scratchpad.extend_from_slice(itoa_buf.format(price).as_bytes());
    }

    scratchpad.push(b'\n');
    let _ = out.write_all(scratchpad);
    Ok(())
}


#[inline(never)]
pub fn print_quote_str<W: Write>(
    out: &mut W,
    quote: &QuotePacketView,
    pkt_time: u64,
    accept_time: u64,
) -> io::Result<()> {

    let (bid_price1, bid_qty1) = quote.bid(0);
    let (bid_price2, bid_qty2) = quote.bid(1);
    let (bid_price3, bid_qty3) = quote.bid(2);
    let (bid_price4, bid_qty4) = quote.bid(3);
    let (bid_price5, bid_qty5) = quote.bid(4);

    let (ask_price1, ask_qty1) = quote.ask(0);
    let (ask_price2, ask_qty2) = quote.ask(1);
    let (ask_price3, ask_qty3) = quote.ask(2);
    let (ask_price4, ask_qty4) = quote.ask(3);
    let (ask_price5, ask_qty5) = quote.ask(4);
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
