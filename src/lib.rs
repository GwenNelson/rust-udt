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

pub enum UdtSockType {
    STREAM,
    DGRAM
}

pub struct UDTSOCKET {
    raw_sock: UdpSocket,
    sock_type: UdtSockType,
}

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


