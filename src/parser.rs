#[derive(Clone, Copy, Debug, PartialEq)]
enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum TsResolution {
    Micro,
    Nano,
}

#[derive(Clone, Copy, Debug)]
pub struct PcapMeta {
    endian: Endianness,
    ts_res: TsResolution,
}

// https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html
fn parse_global_header(mmap: &[u8]) -> PcapMeta {
    if mmap.len() < 24 {
        panic!("File is too small to be a valid PCAP");
    }

    // Matching raw bytes avoids endian-conversion confusion during the magic check
    match &mmap[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => PcapMeta {
            endian: Endianness::Little,
            ts_res: TsResolution::Micro,
        },
        [0xa1, 0xb2, 0xc3, 0xd4] => PcapMeta {
            endian: Endianness::Big,
            ts_res: TsResolution::Micro,
        },
        [0x4d, 0x3c, 0xb2, 0xa1] => PcapMeta {
            endian: Endianness::Little,
            ts_res: TsResolution::Nano,
        },
        [0xa1, 0xb2, 0x3c, 0x4d] => PcapMeta {
            endian: Endianness::Big,
            ts_res: TsResolution::Nano,
        },
        _ => panic!("Invalid PCAP magic number"),
    }
}

#[repr(C)]
pub struct PcapPktHdr {
    pub ts_sec: u32,  // Since EPOCH
    pub ts_usec: u32, // Since EPOCH
    pub incl_len: u32,
    pub orig_len: u32,
}

impl PcapPktHdr {
    #[inline(always)]
    fn read_u32(bytes: &[u8], endian: Endianness) -> u32 {
        match endian {
            Endianness::Little => u32::from_le_bytes(bytes.try_into().unwrap()),
            Endianness::Big => u32::from_be_bytes(bytes.try_into().unwrap()),
        }
    }

    // Little endian
    #[inline(always)]
    fn parse_pkt_hdr(bytes: &[u8], meta: &PcapMeta) -> PcapPktHdr {
        PcapPktHdr {
            ts_sec: Self::read_u32(&bytes[0..4], meta.endian),
            ts_usec: Self::read_u32(&bytes[4..8], meta.endian),
            incl_len: Self::read_u32(&bytes[8..12], meta.endian),
            orig_len: Self::read_u32(&bytes[12..16], meta.endian),
        }
    }
}

pub struct CustomPcapReader<'a> {
    pub mmap: &'a [u8],
    pub offset: usize,
    pub meta: PcapMeta,
}

impl<'a> CustomPcapReader<'a> {
    pub fn new(mmap: &'a [u8]) -> Self {
        let meta = parse_global_header(mmap);
        Self {
            mmap,
            offset: 24,
            meta,
        }
    }
}

impl<'a> Iterator for CustomPcapReader<'a> {
    type Item = (PcapPktHdr, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 16 > self.mmap.len() {
            return None;
        }

        let hdr_bytes = &self.mmap[self.offset..self.offset + 16];

        // Added PcapPktHdr:: prefix
        let hdr = PcapPktHdr::parse_pkt_hdr(hdr_bytes, &self.meta);

        self.offset += 16;

        let len = hdr.incl_len as usize;

        if self.offset + len > self.mmap.len() {
            // returning None cleanly ends the iterator.
            return None;
        }

        let packet = &self.mmap[self.offset..self.offset + len];

        self.offset += len;

        Some((hdr, packet))
    }
}
