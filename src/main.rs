use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::io::Read;

use ansi_term::Colour::Red;
use ansi_term::Colour::Blue;
use ansi_term::Colour::Green;
use ansi_term::Colour::White;


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
fn main() {

    // let dummy: [u8;32] = [ 0x01, 0x02, 0x03, 0x02, 0x01, 0x10, 0x17, 0xff, 0xff, 0x00, 0x00, 0x08, 0x0f, 0x00, 0x00, 0x7a, 0x69, 0xff, 0xff, 0x91, 0xc0, 0xd1, 0x3b, 0xee, 0xa3, 0xef, 0x56, 0x60, 0x17, 0x88, 0x87, 0x50 ];


    let path = "5545.pcap";

    let prepend: [u8;1] = [ 0x45 ];

    let mut file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).expect("PcapNGReader");
    
    let mut hdrcnt: [usize; 0x10000] = [0; 65536];

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
                        // use linktype to parse b.data()
                        // println!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", b.data[0], b.data[1], b.data[2], b.data[3], b.data[4], b.data[5]);
                        // parse_packet(b.data, 3);

                        let mut pack: [u8;32] = [0;32];
                        let pl = prepend.len();
                        for i in 0..pl {
                            pack[i] = prepend[i];
                        }
                        for i in pl..32 {
                            pack[i] = b.data[i-pl];
                        }



                        examine(&pack);
                        // parse_packet(b.data, 4);
                        // parse_packet(b.data, 5);
                        // let addr: usize = (b.data[0] as usize) << 8 | b.data[1] as usize;
                        // hdrcnt[addr] += 1;

                    },
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            },
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);

    for i in 0..65536 {
        if hdrcnt[i] > 9 {
            println!("{:04x}: {}", i, hdrcnt[i]);
        }

    }

}



fn examine(p: &[u8]) {

    for hdr in 3..6 {
        for dlen in 1..(30-hdr) {
            examine_as_simple_shockburst(p, hdr, dlen);
            examine_as_enhanced_shockburst(p, hdr, dlen);
        }
    }
}







fn examine_as_simple_shockburst(p: &[u8], hdrlen: usize, datalen: usize) {

    if p.len() < 32 { println!("small pack"); return; }
    let head = header64(p,hdrlen);
    let calc_crc  = crc16(p, (hdrlen+datalen)*8);
    let pack_crc = (p[hdrlen+datalen] as u16) << 8 | p[hdrlen+datalen+1] as u16;

    if calc_crc == pack_crc {
        println!("s {}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc, Green.paint(format!("{:04x}", pack_crc)));
    } else {
        // println!("{}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc, Red.paint(format!("{:04x}", pack_crc)));
    }



}

fn examine_as_enhanced_shockburst(p: &[u8], hdrlen: usize, datalen: usize) {

    if p.len() < 32 { println!("small pack"); return; }
    let head = header64(p,hdrlen);
    let calc_crc  = crc16(p, ((hdrlen+datalen)*8) + 9 );

    let shifted = shift_left(p);
    let pack_crc = (shifted[hdrlen+datalen+1] as u16) << 8 | shifted[hdrlen+datalen+2] as u16;

    if calc_crc == pack_crc {
        println!("e {}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc, Green.paint(format!("{:04x}", pack_crc)));
    } else {
        // println!("{}/{} {:012x} => {:04x} ({})", hdrlen, datalen, head, calc_crc, Red.paint(format!("{:04x}", pack_crc)));
    }



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