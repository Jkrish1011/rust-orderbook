pub const QUOTE_PACKET_SIZE: usize = 215;
pub const QUOTE_PREFIX: &[u8; 5] = b"B6034";
pub const ISSUE_CODE_META: &[usize; 2] = &[5, 12]; // OFFSET_VALUE, LENGTH
pub const ACCEPT_TIME_META: &[usize; 2] = &[206, 8];
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
    pub fn issue_code(&self) -> &'a str {
        std::str::from_utf8(&self.raw[ISSUE_CODE_META[0]..(ISSUE_CODE_META[0] + ISSUE_CODE_META[1])]).unwrap()
    }

    #[inline(always)]
    pub fn accept_time(&self) -> u64 {
        let time_ref = &self.raw[ACCEPT_TIME_META[0]..(ACCEPT_TIME_META[0]+ACCEPT_TIME_META[1])];

        let hh = (time_ref[0] as u64 - 48) * 10 + (time_ref[1] as u64 - 48);
        let mm = (time_ref[2] as u64 - 48) * 10 + (time_ref[3] as u64 - 48);
        let ss = (time_ref[4] as u64 - 48) * 10 + (time_ref[5] as u64 - 48);
        let uu = (time_ref[6] as u64 - 48) * 10 + (time_ref[7] as u64 - 48);

        let total_secs = hh * 3600 + mm * 60 + ss;
        (total_secs * 1_000_000) + (uu * 10_000)
    }
}
