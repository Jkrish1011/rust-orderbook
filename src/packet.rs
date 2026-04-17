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

#[derive(Debug, Clone)]
pub struct QuotePacketView<'a> {
    raw: &'a [u8],
}

impl<'a> QuotePacketView<'a> {
    #[inline(always)]
    pub fn try_new(raw: &'a [u8]) -> Option<Self> {
        if raw.len() == 215 && &raw[0..5] == QUOTE_PREFIX && raw[END_OF_PACKET] == 0xFF {
            Some(Self { raw })
        } else {
            None
        }
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
        std::str::from_utf8(&self.raw[ISSUE_CODE_META[0]..(ISSUE_CODE_META[0] + ISSUE_CODE_META[1])]).unwrap()
    }

    #[inline(always)]
    pub fn accept_time(&self) -> u64 {
        
        // let time_ref1 = std::str::from_utf8(&self.raw[ACCEPT_TIME_META[0]..(ACCEPT_TIME_META[0]+ACCEPT_TIME_META[1])]).unwrap();
        // let hh = time_ref1[0..2].parse::<u64>().unwrap();
        // let mm = time_ref1[2..4].parse::<u64>().unwrap();
        // let ss = time_ref1[4..6].parse::<u64>().unwrap();
        // let uu = time_ref1[6..8].parse::<u64>().unwrap();

        // // Formula: (hours * 3600 + minutes * 60 + seconds) * 1,000,000 + microseconds
        // let t = (hh * 3600 + mm * 60 + ss) * 1_000_000 + uu;
        let time_ref = &self.raw[ACCEPT_TIME_META[0]..(ACCEPT_TIME_META[0]+ACCEPT_TIME_META[1])];
        
        // Explore get_unchecked to unlock more speed
        let hh = (time_ref[0] as u64 - 48) * 10 + (time_ref[1] as u64 - 48);
        let mm = (time_ref[2] as u64 - 48) * 10 + (time_ref[3] as u64 - 48);
        let ss = (time_ref[4] as u64 - 48) * 10 + (time_ref[5] as u64 - 48);
        let uu = (time_ref[6] as u64 - 48) * 10 + (time_ref[7] as u64 - 48);

        // let total_secs = hh * 3600 + mm * 60 + ss;
        // let t2 = (total_secs * 1_000_000) + (uu);
        // println!("t1: {} || t2: {}", t, t2);
        // ( hh * 3600 + mm * 60 + ss ) * 1_000_000 + uu
        (hh * 3600 + mm * 60 + ss) * 1_000_000 + (uu * 10_000) // Normalize uu to micro seconds
    }

    #[inline(always)]
    pub fn bid(&self, level: usize) -> (u32, u32) {
        let base = level * LEVEL_STRIDE;
        let price_start = BID_FIRST_PRICE_META[0] + base;
        let qty_start = BID_FIRST_QTY_META[0] + base;

        let price = Self::parse_ascii_to_u32(&self.raw[price_start..(price_start + BID_FIRST_PRICE_META[1])]);
        let qty = Self::parse_ascii_to_u32(&self.raw[qty_start..(qty_start + BID_FIRST_QTY_META[1])]);
        
        (price, qty)
    }

    #[inline(always)]
    pub fn ask(&self, level: usize) -> (u32, u32) {
        let base = level * LEVEL_STRIDE;
        let price_start = ASK_FIRST_PRICE_META[0] + base;
        let qty_start = ASK_FIRST_QTY_META[0] + base;

        let price = Self::parse_ascii_to_u32(&self.raw[price_start..(price_start + ASK_FIRST_PRICE_META[1])]);
        let qty = Self::parse_ascii_to_u32(&self.raw[qty_start..(qty_start + ASK_FIRST_QTY_META[1])]);
        
        (price, qty)
    }
}
