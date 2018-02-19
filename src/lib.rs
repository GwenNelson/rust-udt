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
extern crate nom;

use nom::be_u32;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::UdpSocket;

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
#[derive(PartialEq)]
pub enum UDTSockType {
    STREAM,
    DGRAM
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum UDTConnType {
    Regular,
    Rendezvous
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum ControlPacketType {
    Handshake,
    KeepAlive,
    Ack,
    NegativeAck,
    Unused,
    Shutdown,
    AckAck,
    MsgDropRequest,
    Custom,
    Bacon, // as with DataSeqType, this is the "WTF?" value
}

impl From<u16> for ControlPacketType {
     fn from(controlpackettype: u16) -> ControlPacketType {
        match controlpackettype {
           0x0    => ControlPacketType::Handshake,
           0x1    => ControlPacketType::KeepAlive,
           0x2    => ControlPacketType::Ack,
           0x3    => ControlPacketType::NegativeAck,
           0x4    => ControlPacketType::Unused,
           0x5    => ControlPacketType::Shutdown,
           0x6    => ControlPacketType::AckAck,
           0x7    => ControlPacketType::MsgDropRequest,
           0x7FFF => ControlPacketType::Custom,
           _      => ControlPacketType::Bacon,
        }
     }
}

// the below is not the standard "rusty" way to do things, I know
// it's here for a reason
#[derive(Debug)]
pub enum ControlPacketInfo {
    Handshake {
        UDTVersion: u32,
        SockType: UDTSockType,
        InitialSeqNo: u32,
        MTU: u32,
        MaxFlowWindow: u32,
        ConnType: UDTConnType,
        SocketID: u32,
        SynCookie: u32,
        PeerIP: IpAddr,
    },
    KeepAlive,
    Ack {
        SeqNo: u32,
        RTT: u32,
        RTTVariance: u32,
        AvailBufferSize: u32,
        RxPacketsPerSecond: u32,
        LinkCapacity: u32,
    },
    NegativeAck {
        LossInformation: u32,
    },
    Unused,
    Shutdown {
        SeqNo: u32,
    },
    AckAck {
        MsgID: u32,
        FirstSeqNo: u32,
        LastSeqNo: u32,
    },
    Custom,
    Bacon, // placeholder/WTF value
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

#[derive(Debug)]
pub struct UDTControlPacketHeader {
    pub PacketType: ControlPacketType,
    pub CustomType: u16,
    pub AdditionalInfo: u32,
    pub timestamp: u32,
    pub dest_socket_id: u32,
    pub control_info: ControlPacketInfo,
}

pub struct UDTSOCKET {
    raw_sock: UdpSocket,
    sock_type: UDTSockType,
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

named!(pub parse_control_packet_header_a<&[u8], UDTControlPacketHeader>, do_parse!(
        controlflag_and_type:  bits!(tuple!(take_bits!(u8,1), take_bits!(u16,15), take_bits!(u16,16))) >>
        additional_info_field: bits!(take_bits!(u32,29)) >>
        timestamp_val:         be_u32 >>
        id_val:                be_u32 >>
        (UDTControlPacketHeader {
           PacketType: ControlPacketType::from(controlflag_and_type.1),
           CustomType: controlflag_and_type.2,
           AdditionalInfo: additional_info_field,
           timestamp: timestamp_val,
           dest_socket_id: id_val,
           control_info: ControlPacketInfo::Bacon,
        })
));

pub fn startup() -> u16 {
    return 0;
}

pub fn cleanup() -> u16 {
    return 0;
}

pub fn parse_control_packet_header(data: &[u8]) -> UDTControlPacketHeader {
    let parsed_header: UDTControlPacketHeader = parse_control_packet_header_a(data).to_result().unwrap();
    match parsed_header.PacketType {
          ref Handshake => {
              let parsed_handshake: UDTControlPacketHeader = parse_control_packet_header_a(data).to_result().unwrap(); // this is unbelievably dumb, blame rust's move semantics, my C++ background and rushed development
              return UDTControlPacketHeader {
                    PacketType: parsed_handshake.PacketType,
                    CustomType: parsed_handshake.CustomType,
                    AdditionalInfo: parsed_handshake.AdditionalInfo,
                    timestamp: parsed_handshake.timestamp,
                    dest_socket_id: parsed_handshake.dest_socket_id,
                    control_info: ControlPacketInfo::Handshake {
                        UDTVersion: 0,
                        SockType: UDTSockType::DGRAM,
                        InitialSeqNo: 0,
                        MTU: 0,
                        MaxFlowWindow: 0,
                        ConnType: UDTConnType::Regular,
                        SocketID: 0,
                        SynCookie: 0,
                        PeerIP: IpAddr::V4(Ipv4Addr::new(127,0,0,1)), 
                   }
               }
          },
          _ => {
          },
    }
    return parsed_header;
}

pub fn socket(sock_type: UDTSockType, bind_addr: String) -> UDTSOCKET {
    let raw = UdpSocket::bind(bind_addr).unwrap();
    let retval: UDTSOCKET = UDTSOCKET { raw_sock: raw, sock_type: sock_type};
    return retval;
}


