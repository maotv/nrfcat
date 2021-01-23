use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::io::Read;

use ansi_term::{ANSIGenericString, Colour};
use ansi_term::Style;
use std::fmt::Write;

fn xmain() {

    // let dummy: [u8;32] = [ 0x01, 0x02, 0x03, 0x02, 0x01, 0x10, 0x17, 0xff, 0xff, 0x00, 0x00, 0x08, 0x0f, 0x00, 0x00, 0x7a, 0x69, 0xff, 0xff, 0x91, 0xc0, 0xd1, 0x3b, 0xee, 0xa3, 0xef, 0x56, 0x60, 0x17, 0x88, 0x87, 0x50 ];
//    let dummy: [u8;32] = [ 0x01, 0x02, 0x03, 0x02, 0x01, 0x10, 0x17, 0xff, 0x55, 0x00, 0x00, 0x08, 0x79, 0x00, 0x00, 0x7a, 0x69, 0xff, 0xff, 0x95, 0x69, 0xcc, 0x24, 0x57, 0x95, 0xb4, 0xfd, 0x99, 0x9e, 0x2a, 0x2f, 0x56 ];
    // let dummy: [u8;32] = [ 0x01, 0x02, 0x03, 0x02, 0x01, 0x10, 0x17, 0xff, 0x55, 0x00, 0x00, 0x09, 0x05, 0x00, 0x00, 0x7a, 0x69, 0xff, 0xff, 0x04, 0xb0, 0xe1, 0x2e, 0x0e, 0x94, 0x55, 0x60, 0x93, 0x54, 0xb9, 0x4d, 0x6c];
    
    let dummy: [u8;32] = [ 0x45, 0x44, 0x43, 0x42, 0x41, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x68, 0x3e, 0x1b, 0x5b, 0x5d, 0xc4, 0xb5, 0xf7, 0xaa, 0xde, 0xf2, 0xa6, 0xe4, 0x7e, 0x73, 0xbb, 0x22, 0x7f, 0xde, 0x75, 0x7a, 0x6f ];
        // let dummy: [u8;32] = [ 0x45, 0x44, 0x43, 0x42, 0x41, 0x84, 0x04, 0x00, 0x00, 0x5d, 0xd4, 0x37, 0xb3, 0xff, 0xdf, 0xd0, 0x77, 0x6d, 0xb6, 0xa8, 0xdb, 0x53, 0x5d, 0x6d, 0xd3, 0x2b, 0x2d, 0x52, 0xdb, 0x5d, 0x9d, 0xb5 ];

    //let xdummy: [u8;1] = [ 0x01 ];
    println!("{:x?}", dummy);
    println!("{:x?}", shift_left(&dummy));
    
    examine(&dummy);

//     let cs = State::<X_25>::calculate(&dummy[0..11]);
//     println!("lib: {:04x}", cs)

}

#[derive(Debug)]
enum CRC {
    None,
    U8(u8),
    U16(u16)
}

#[derive(Debug)]
enum PacketKind {
    Simple,
    Enhanced
}

#[derive(Debug)]
struct PacketInfo {
    kind: PacketKind,
    length: usize,
    crc: CRC,
    data: Vec<u8>
}

struct Statistics {
    ts_first: u32,
    ts_last: u32,
    count: u32,
    maxh: u32, // higest number of headers with same addr
    maxa: u32, // address with highest number of packets
    addrcnt: [u32;0x10000]
}

impl Statistics {

    fn new() -> Self {
        Statistics {
            ts_first: 0,
            ts_last: 0,
            count: 0,
            maxh: 2, // init with 2, so we see only adresses with 3 or more packets
            maxa: 0,
            addrcnt: [0;0x10000]
        }
    }
}

enum ANSI {
    Normal,
    Dark
}

// fn style(c: ANSI, t: String) -> ANSIGenericString<str> {


// }

fn write_packet_noinfo(hdr: &LegacyPcapBlock, data: &[u8], cnt: u32) {

    println!("{:05}.{:03} | - | {} | {} | {} | HCNT {}", hdr.ts_sec&0xffff, hdr.ts_usec/1000,
        Colour::Blue.paint(format!("{:02x} {:02x} {:02x}", data[0], data[1], data[2])),
        Colour::Blue.paint(format!("{:02x} {:02x}", data[3], data[4])),
        Colour::Blue.paint(format!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", 
            data[5], data[6], data[7], 
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], 
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        )),
        cnt
    );
}
fn write_packet_info(hdr: &LegacyPcapBlock, p: &[u8], info: &PacketInfo, cnt: u32) {

//    let tx = match info.type
    let data = &info.data;


    if info.length < 6 {
        println!("{:05}.{:03} | - | {} | {} | {} | HCNT {}", hdr.ts_sec&0xffff, hdr.ts_usec/1000,
        Colour::Blue.paint(format!("{:02x} {:02x} {:02x}", data[0], data[1], data[2])),
        Colour::Blue.paint(format!("{:02x} {:02x}", data[3], data[4])),
        Colour::Red.paint(format!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", 
            data[5], data[6], data[7], 
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], 
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        )),
        cnt
    );
        return;
    }

    // println!("{:?}", info);

    let se = match info.kind {
        PacketKind::Simple => "s",
        PacketKind::Enhanced => "e",
        _ => "-"
    };

    let pckt = format!("XA XB XC XD XE {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} ", 
        data[5], data[6], data[7], 
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], 
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
    );

    let crclength = match info.crc {
        CRC::U8(c) => 1,
        CRC::U16(c) => 2,
        CRC::None => 0,
    };

    let realp = &pckt[5*3..info.length*3];
    let crcs = match info.crc {
        CRC::U8(c) => format!("{:02x}", data[info.length]),
        CRC::U16(c) => format!("{:02x} {:02x}", data[info.length], data[info.length+1]),
        CRC::None => format!(""),
    };

    let rest = &pckt[(info.length+crclength)*3..32*3];



    let ascii: String = data.iter().map(|c| {
        match c {
            32..=126 => *c as char,
            _=> '.'
        }
    }).collect();



    println!("{:05}.{:03} | {} | {} | {} | {}{} {}| {} HC/{}", hdr.ts_sec&0xffff, hdr.ts_usec/1000, se, 
        Colour::Green.paint(format!("{:02x} {:02x} {:02x}", data[0], data[1], data[2])),
        Colour::Blue.paint(format!("{:02x} {:02x}", data[3], data[4])),
        Colour::Cyan.paint(realp),
        Colour::Red.paint(crcs),
        Colour::Blue.paint(rest),
        // Colour::Blue.paint(format!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", 
        //     data[5], data[6], data[7], 
        //     data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], 
        //     data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        //     data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            
        //  )),
        ascii,
        cnt
        
    );
}


fn build_packet_string(data: &[u8], pi: Option<PacketInfo>) {

    let mut out = String::with_capacity(256);

    // let base_hdr = match hdr {
    //     true => Colour::Green.normal().paint(format!("{:02x} {:02x} {:02x}", data[0], data[1], data[2])),
    //     false => Style::new().paint(format!("{:02x} {:02x} {:02x}", data[0], data[1], data[2]))
    // };


    for i in 3..32 {
//        if i > length {
            // write!(out, "{} ", style(ANSI::Dark, &format!("{:02x}", data[i])) );
//        }

    }


    // Colour::Green.paint(format!("{:04x}", pack_crc);


}

fn process(pcnt: u32, pcap: &LegacyPcapBlock,mut st: Statistics) -> Statistics 
{

    let data = pcap.data;

    // packet counter
    st.count += 1;

    // first three header bytes as u32
    let h32: u32 = (data[0] as u32) << 16 | (data[1] as u32) << 8 | data[2] as u32;

    // 2 header lsb for counting
    let h16: usize = (h32&0xffff) as usize;

    // count this header
    st.addrcnt[h16] += 1;

    if st.addrcnt[h16] > st.maxh {
        st.maxh = st.addrcnt[h16];
        st.maxa = h16 as u32;
    }

    let info = examine(data);
    

    match info {
        Some(i) => {
            match i.crc {
                CRC::U16(_) => {
                    write_packet_info(pcap, data, &i, st.addrcnt[h16]);
                },
                CRC::U8(_) => {
                    if  st.addrcnt[h16] > 1 {
                        write_packet_info(pcap, data, &i, st.addrcnt[h16]);
                    }
                },
                CRC::None => {
                    if  st.addrcnt[h16] > 2 {
                        write_packet_noinfo(pcap, data, st.addrcnt[h16]);
                    }
                }
            }


            
        }
        None => {
            if  st.addrcnt[h16] > 2 {
                write_packet_noinfo(pcap, data, st.addrcnt[h16]);
            }
        }
    }


    // if info.is_some() {



    //     write_packet_info(pcap, data, &info.expect("checked above"), st.addrcnt[h16]);
    // } else if  st.addrcnt[h16] > 2 {
    //     write_packet_noinfo(pcap, data, st.addrcnt[h16]);
    // } else {
    //     // ???
    // }


    // if must_show {
    //     println!("{:6} | {:02x} {:02x} {:02x} | {:02x} {:02x} | {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} | MAX [??{:04x}] {}", 
    //         pcnt, data[0], data[1], data[2], data[3], data[4],
    //         data[5], data[6], data[7], 
    //         data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], 
    //         data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    //         data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
    //         st.maxa, st.maxh
    //     );

    // }


    st
    
}

// Channel: 32
// Header:  55 01 22 
// Packets: 245 (pps: 12,5)
// MaxSame:  33 (13,5%)

 fn report(st: &Statistics) {

    println!("");
    // println!("# Report");
    // println!("# Channel: {}, Address: {}", 0, 0);

    println!("Valid/Multiple/Total");

    for i in 0..65536 {
        if st.addrcnt[i] > 9 {
            println!("[ ?? {:02x} {:02x} ] -> {}", i>>8, i&0xff, st.addrcnt[i]);
        }
    }
    println!("--- end ----------------------------------------------------------------");
    println!("");
}

fn main() {

    // let dummy: [u8;32] = [ 0x01, 0x02, 0x03, 0x02, 0x01, 0x10, 0x17, 0xff, 0xff, 0x00, 0x00, 0x08, 0x0f, 0x00, 0x00, 0x7a, 0x69, 0xff, 0xff, 0x91, 0xc0, 0xd1, 0x3b, 0xee, 0xa3, 0xef, 0x56, 0x60, 0x17, 0x88, 0x87, 0x50 ];


    // let path = "5545.pcap";

    let prepend: [u8;0] = [ ];

    let stdin = std::io::stdin();

//     let mut file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, stdin).expect("PcapNGReader");
    
    let mut hdrcnt: [usize; 0x10000] = [0; 65536];

    let mut cnt = 0;


    let mut linecnt = 0;

    let mut max = 0;


    let mut stats = Statistics::new();
    let mut allstats: Vec<Statistics> = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                // println!("got new block");
                num_blocks += 1;
                match block {

                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // save hdr.network (linktype)
                    },
                    PcapBlockOwned::Legacy(b) => {

                        if b.data[0] == 0 && b.data[1] == 0 && b.data[2] == 0 {
                            report(&stats);
                            allstats.push(stats);
                            stats = Statistics::new();
                        } else {

                            if stats.ts_first == 0 { stats.ts_first = b.ts_sec; }
                            stats.ts_last = b.ts_sec;

                            

                            stats = process(cnt, &b, stats);
                            cnt += 1;
    
                        }
                    },
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            },
            Err(PcapError::Eof) => {
                report(&stats);
                break
            },
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);

    

}



fn examine(p: &[u8]) -> Option<PacketInfo> {

    let mut valid = false;

    for hdr in 3..6 {
        for dlen in 1..(30-hdr) {
            let rv = match examine_as_simple_shockburst(p, hdr, dlen) {
                Some(pi) => Some(pi),
                None => examine_as_enhanced_shockburst(p, hdr, dlen)
            };

            if rv.is_some() { return rv; }

        }
    }

    None

}





fn examine_as_simple_shockburst(p: &[u8], hdrlen: usize, datalen: usize) -> Option<PacketInfo> {

    if p.len() < 32 { println!("small pack"); return None; }
    let head = header64(p,hdrlen);
    let calc_crc_16  = crc16(p, (hdrlen+datalen)*8);
    let calc_crc_8  = crc8(p, (hdrlen+datalen)*8);

    let pack_crc_16 = (p[hdrlen+datalen] as u16) << 8 | p[hdrlen+datalen+1] as u16;
    let pack_crc_8 = p[hdrlen+datalen+1];

    if calc_crc_16 == pack_crc_16 {
        // println!("s {}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc, Colour::Green.paint(format!("{:04x}", pack_crc)));
        Some(PacketInfo {
            kind: PacketKind::Simple,
            length: (hdrlen + datalen),
            crc: CRC::U16(calc_crc_16),
            data: Vec::from(p)
        })

    } else if calc_crc_8 == pack_crc_8 {
            // println!("e {}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc_8, Colour::Green.paint(format!("{:04x}", pack_crc_8)));
            Some(PacketInfo {
                kind: PacketKind::Enhanced,
                length: hdrlen + datalen,
                crc: CRC::U8(calc_crc_8),
                data: Vec::from(p)
            })
    } else {
        // println!("{}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc, Red.paint(format!("{:04x}", pack_crc)));
        None
    }

}

fn examine_as_enhanced_shockburst(p: &[u8], hdrlen: usize, datalen: usize) -> Option<PacketInfo> {

    if p.len() < 32 { println!("small pack"); return None; }
    let head = header64(p,hdrlen);
    let calc_crc_16  = crc16(p, ((hdrlen+datalen)*8) + 9 );
    let calc_crc_8  = crc8(p, ((hdrlen+datalen)*8) + 9 );

    let shifted = shift_left(p);
    let pack_crc_16 = (shifted[hdrlen+datalen+1] as u16) << 8 | shifted[hdrlen+datalen+2] as u16;
    let pack_crc_8 = shifted[hdrlen+datalen+1];

    let mut datav = Vec::with_capacity(32);
    datav.extend_from_slice(&p[0..5]);

    if calc_crc_16 == pack_crc_16 {
        
        // println!("e {}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc_16, Colour::Green.paint(format!("{:04x}", pack_crc_16)));
        datav.extend_from_slice(&shifted[5..32]);
        Some(PacketInfo {
            kind: PacketKind::Enhanced,
            length: hdrlen + datalen + 1,
            crc: CRC::U16(calc_crc_16),
            data: datav
        })
    } else if calc_crc_8 == pack_crc_8 {
            // println!("e {}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc_8, Colour::Green.paint(format!("{:04x}", pack_crc_8)));
            datav.extend_from_slice(&shifted[5..32]);
            Some(PacketInfo {
                kind: PacketKind::Enhanced,
                length: hdrlen + datalen + 1,
                crc: CRC::U8(calc_crc_8),
                data: datav
            })
        } else {
        None
        // println!("{}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc, Red.paint(format!("{:04x}", pack_crc)));
    }

//    calc_crc == pack_crc

}


fn shift_left(p: &[u8]) -> [u8;32] {

    if p.len() < 32 { panic!(); }

    let mut overflow: u8 = 0;
    let mut shifted: [u8; 32] = [0;32]; 

    for i in 0..32 {
        shifted[31-i] = (p[31-i] << 1) | overflow;
        overflow = p[31-i] >> 7;
    }

    shifted

}


fn header64(p: &[u8], hdrlen: usize) -> u64 {
    let head: u64 = match hdrlen {
        3 => (p[0] as u64)<<16 | (p[1] as u64)<<8 | (p[2] as u64),
        4 => (p[0] as u64)<<24 | (p[1] as u64)<<16 | (p[2] as u64)<<8 | (p[3] as u64),
        5 => (p[0] as u64)<<32 | (p[1] as u64)<<24 | (p[2] as u64)<<16 | (p[3] as u64)<<8 | (p[4] as u64),
        _ => 0
    };
    head
}

fn parse_enhanced(p: &[u8], hdrlen: usize) {

    if p.len() < 32 { println!("small pack"); return; }

    let head: u64 = match hdrlen {
        3 => (p[0] as u64)<<16 | (p[1] as u64)<<8 | (p[2] as u64),
        4 => (p[0] as u64)<<24 | (p[1] as u64)<<16 | (p[2] as u64)<<8 | (p[3] as u64),
        5 => (p[0] as u64)<<32 | (p[1] as u64)<<24 | (p[2] as u64)<<16 | (p[3] as u64)<<8 | (p[4] as u64),
        _ => 0
    };

    let pcf = p[hdrlen];

    let plen = (pcf&0xFC)>>2;
    let pid = pcf&0x03;
    let nack = (p[hdrlen+1] & 0x80) >> 7;





}

fn tvb_get_guint8(p: &[u8], offs: usize) -> u8 {
    // println!("tvb_get_guint8({}) -> {:02x}", offs, p[offs]);
    p[offs]
}



fn crc8(p: &[u8], len_bits: usize) -> u8
{
    let mut crc: u8 = 0xff; 

    if (len_bits > 0) && (len_bits <= p.len() * 8) // bytes to bits
    {
        // The length of the data might not be a multiple of full bytes.
        // Therefore we proceed over the data bit-by-bit (like the NRF24 does) to
        // calculate the CRC.
        // let mut data: u16 = 0;
        // let mut byte: u8  = 0;
        // let mut shift: u8 = 0;
        let mut bitoffs: usize = 0;

        // Get a new byte for the next 8 bits.
        let mut byte: u8 = tvb_get_guint8(p, bitoffs>>3);

        while bitoffs < len_bits
        {

            let shift = (bitoffs & 7) as u8;

            // Shift the active bit to the position of bit 7 
            // Assure all other bits are 0
            let active_bit = (byte << shift) & 0x80;
            // data &= 0x8000;
            // println!("Data is {:04x}", data);

            crc = crc ^ active_bit;
            if (crc & 0x80) > 0 {
                crc = (crc << 1) ^ 0x07;      // (1) 0000 0111 x^8 + x^2 + x + 1 // 0x1021 = (1) 0001 0000 0010 0001 = x^16+x^12+x^5+1
            } else {
                crc = crc << 1;
            }

            // println!("{:02} Data/CRC {:04x} {:04x}", bitoffs, active_bit, crc);


            bitoffs += 1;
            if 0 == (bitoffs & 7) {
                // Get a new byte for the next 8 bits.
                byte = tvb_get_guint8(p, bitoffs>>3);
            }
        }
    }

    return crc;



    // crc = (crc << 1) ^ 0x1021;      // 0x1021 = (1) 0001 0000 0010 0001 = x^16+x^12+x^5+1
    // crc = (crc << 1) ^ 0x1021;      // 0x1021 = (1) 0001 0000 0010 0001 = x^16+x^12+x^5+1
    //                                                    1    0    2    1

    //                                                    (1) 0000 0101

    // 0
}



fn crc16(p: &[u8], len_bits: usize) -> u16
{

    let mut crc: u16 = 0xffff;

    if (len_bits > 0) && (len_bits <= p.len() * 8) // bytes to bits
    {
        // The length of the data might not be a multiple of full bytes.
        // Therefore we proceed over the data bit-by-bit (like the NRF24 does) to
        // calculate the CRC.
        // let mut data: u16 = 0;
        // let mut byte: u8  = 0;
        // let mut shift: u8 = 0;
        let mut bitoffs: usize = 0;

        // Get a new byte for the next 8 bits.
        let mut byte: u8 = tvb_get_guint8(p, bitoffs>>3);

        while bitoffs < len_bits
        {

            let shift = (bitoffs & 7) as u8;

            // Shift the active bit to the position of bit 15 
            // Assure all other bits are 0
            let active_bit = ((byte as u16) << (8 + shift)) & 0x8000;
            // data &= 0x8000;
            // println!("Data is {:04x}", data);

            crc = crc ^ active_bit;
            if (crc & 0x8000) > 0 {
                crc = (crc << 1) ^ 0x1021;      // 0x1021 = (1) 0001 0000 0010 0001 = x^16+x^12+x^5+1
            } else {
                crc = crc << 1;
            }

            // println!("{:02} Data/CRC {:04x} {:04x}", bitoffs, active_bit, crc);


            bitoffs += 1;
            if 0 == (bitoffs & 7) {
                // Get a new byte for the next 8 bits.
                byte = tvb_get_guint8(p, bitoffs>>3);
            }
        }
    }

    return crc;
}


// def validmac(self,packet):
//         sync=self.client.RF_getsmac()&0xFF;
//         mac=self.packetaddr(packet,justmac=True);
        
//         #BT preamble is A or 5.
//         #Fix this to work on the smallest bit, not the highest.
//         if ((ord(packet[0])&0x80)^(sync&0x80)) and self.macreject:
//             #print "%02x%02x invalid entry." % (sync,ord(packet[0]));
//             #This is a special kind of failure.  Freq is probably right, but MAC is wrong.
//             return False;
//         blacklist=['5555555555', 'aaaaaaaaaa',
//                    '0000000000', 'ffffffffff',
//                    '55555555',   'aaaaaaaa',
//                    '00000000',   'ffffffff',
//                    '555555',     'aaaaaa',
//                    '000000',     'ffffff',
//                    '7fffff', 'aaffff', 'aaaaff',
//                    'afffff', 'abffff', '5fffff'];
//         for foo in blacklist:
//             if mac==foo:
//                 return False;
//         return True;