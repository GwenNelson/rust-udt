/* MIT License
 * 
 * Copyright (c) 2018 Gareth Nelson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#[macro_use]
extern crate bitfield;

#[macro_use]
extern crate nom;

use nom::be_u32;

use std::net::UdpSocket;

bitfield!{
    pub struct UdtDataPacketHeader(MSB0 [u8]);
    impl Debug;
    u32;
    pub dataflag, set_dataflag: 0;
    pub seq_num, set_seq_num: 1, 31;
    pub pkt_pos, set_pkt_pos: 32, 35;
    pub msg_num, set_msg_num: 36, 63;
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum DataSeqType {
    FirstPacket,
    LastPacket,
    OnlyPacket,
    MiddlePacket,
    Bacon, // WTF? This value should never be the case
}

impl From<u8> for DataSeqType {
     fn from(dataseqtype: u8) -> DataSeqType {
        match dataseqtype {
           0b10 => DataSeqType::FirstPacket,
           0b01 => DataSeqType::LastPacket,
           0b11 => DataSeqType::OnlyPacket,
           0b00 => DataSeqType::MiddlePacket,
           _    => DataSeqType::Bacon,
        }
     }
}

#[derive(Debug)]
pub struct UDTDataPacketHeader {
    pub seq_no: u32,
    pub seq_type: DataSeqType,
    pub in_order: bool,
    pub msg_no: u32,
    pub timestamp: u32,
    pub dest_socket_id: u32,
}

pub enum UdtSockType {
    STREAM,
    DGRAM
}

pub struct UDTSOCKET {
    raw_sock: UdpSocket,
    sock_type: UdtSockType,
}

named!(pub parse_data_packet_header<&[u8], UDTDataPacketHeader>, do_parse!(
       dataflag_and_seq: bits!(tuple!(take_bits!(u8,1), take_bits!(u32,31))) >>
       flags_and_msgno:  bits!(tuple!(take_bits!(u8,2), take_bits!(u8,1), take_bits!(u32,29))) >>
       timestamp_val: be_u32 >>
       id_val: be_u32 >>
       (UDTDataPacketHeader {
        seq_no:         dataflag_and_seq.1,
        seq_type:       DataSeqType::from(flags_and_msgno.0),
        in_order:       flags_and_msgno.1 == 1,
        msg_no:         flags_and_msgno.2,
        timestamp:      timestamp_val,
        dest_socket_id: id_val,
        })
));

pub fn startup() -> u16 {
    return 0;
}

pub fn cleanup() -> u16 {
    return 0;
}

pub fn socket(sock_type: UdtSockType, bind_addr: String) -> UDTSOCKET {
    let raw = UdpSocket::bind(bind_addr).unwrap();
    let retval: UDTSOCKET = UDTSOCKET { raw_sock: raw, sock_type: sock_type};
    return retval;
}


