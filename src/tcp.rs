use std::collections::VecDeque;
use std::io;
use std::io::prelude::*;
use bitflags::bitflags;

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug)]
pub enum State {
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
    Closing,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab => true,
            State::FinWait1 => true,
            State::FinWait2 => true,
            State::Closing => true,
            State::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    
    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,   // pub(crate) == protected keyword
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: any state after rcvd FIN, so also  CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        }
        else {
            false
        }
    }
    
    fn availability(&self) -> Available {
        let mut a = Available::empty();

        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }

        // TODO: set Available::write
        // TODO: take into account self.state

        a
    }
}

// TODO fix snd.una
// State of the Send Sequence Space (RFC 793 S3.2 Figure4)

//      1         2          3          4
// ----------|----------|----------|----------
//   SND.UNA    SND.NXT    SND.UNA    SND.WND

// 1 - old sequence numbers which have been acknowledged
// 2 - sequence numbers of unacknowledged data
// 3 - sequence numbers allowed for new data transmission
// 4 - future sequence numbers which are not yet allowed

pub struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    // segment sequence number used for last window update
    wl1: usize,
    // segment acknowledgment number used for last window update
    wl2: usize,
    // initial send sequence number
    iss: u32,
}

// State of the Receive Sequence Space (RFC 793 S3.2 Figure5)

//      1          2          3
// ----------|----------|----------
//  RCV.NXT    RCV.NXT    RCV.WND

// 1 - old sequence numbers which have been acknowledged
// 2 - sequence numbers allowed for new reception
// 3 - future sequence numbers which are not yet allowed

pub struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    //  receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        ip_h: etherparse::Ipv4HeaderSlice<'a>,
        tcp_h: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcp_h.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss: iss,
                una: iss,
                nxt: iss+1,
                wnd: wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_h.sequence_number(),
                nxt: tcp_h.sequence_number() + 1,
                wnd: tcp_h.window_size(),
                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                ip_h.destination().try_into().unwrap(),
                ip_h.source().try_into().unwrap(),
            ),
            tcp: etherparse::TcpHeader::new(
                tcp_h.destination_port(),
                tcp_h.source_port(),
                iss,
                wnd,
            ),
            incoming: Default::default(),
            unacked: Default::default(),
        };

        // needs to start establishing connection
        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[])?;
        Ok(Some(c))
    }


    pub fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<(usize)> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len(),
        );
        self.ip.set_payload_len(size - self.ip.header_len() as usize);

        // checksum calculation
        self.tcp.checksum = self.tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        // write out the headers
        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        nic.send(&buf[..(buf.len() - unwritten)])?;

        Ok(payload_bytes)
    }

    pub fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers
        // TODO handle synchronized RST
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }


    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_h: etherparse::Ipv4HeaderSlice<'a>,
        tcp_h: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first check that sequence numbers are valid (RFC 793 S3.3)
        //
        // valid segment check okay if it acks at least one byte, which means that at least one of the following is true
        // RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND
        // RCV.NXT =< SEG.SEQ + SEG.LEN-1 < RCV.NXT + RCV.WND
        //
        let seqn = tcp_h.sequence_number(); // sequence number
        let mut slen = data.len() as u32;

        if tcp_h.fin() {
            slen += 1;
        }
        if tcp_h.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32); // window end

        let okay = if slen == 0 {
            // zero-length segment has seperate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                }
                else{
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            }
            else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(self.availability());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn.wrapping_add(slen - 1), wend){
                false
            }
            else {
                true
            }
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(self.availability())
        }
        self.recv.nxt = seqn.wrapping_add(slen);

        if !tcp_h.ack() {
            return Ok(self.availability())
        }

        let ackn = tcp_h.acknowledgment_number(); // ack number
        if let State::SynRcvd = self.state {

            if is_between_wrapped(
                self.send.una.wrapping_sub(1), 
                ackn, 
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one ACKed byte
                // and we have only one byte (the SYN)
                self.state = State::Estab;
            }
            else {
                // TODO: RST : <SEQ=SEH.ACK><CTL=RST>
            }
        }
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                self.send.una = ackn;
            }
            // TODO: accept data
            assert!(data.is_empty());


            if let State::Estab = self.state {
                // dbg!(tcp_h.fin());
                // dbg!(self.tcp.fin);

                // now let's end the connection!
                // TODO needs to be stored in retansmission queue!
                self.tcp.fin = true;
                self.write(nic, &[]);
                self.state = State::FinWait1;
            }
        }
        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our fin has been ACKed
                self.state = State::FinWait2;
            }

        }

        if tcp_h.fin() {
            match self.state {
                State::FinWait2 => {
                    // we are done with connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.availability())
    }
}


fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323
    // TCP determines if a data segment is 'old' or new by testing 
    // weather its sequence number is within 2**31 bytes of left edge 
    // of the window, and if it is not disgarding data as old. To 
    // insured that new data is never mistakenly considered old and 
    // vice-versa, the left edge of the sender's windpw has to be at
    // most 2**31 away from the right edge of the receiver's window
    lhs.wrapping_sub(rhs) > 2^31
}


fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}


// fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
//     use std::cmp::Ordering;

//     match start.cmp(&x) {
//         Ordering::Equal => return false,
//         Ordering::Less => {
//             // we have:
//             //
//             // 0 |-------------S---------X-----------------|    (wraparound)
//             //
//             // X is between S and E (S < X < E) in these cases:
//             //
//             // 0 |-------------S---------X------E----------|    (wraparound)
//             //
//             // 0 |--E----------S---------X-----------------|    (wraparound)
//             //
//             // but not in if !(S <= E <= X)
//             //
//             if end >= start && end <= x {
//                 return false;
//             } else {
//                 return true;
//             }
//         }
//         Ordering::Greater => {
//             // we have opposite of above:
//             //
//             // 0 |-------------X---------S-----------------|    (wraparound)
//             //
//             // X is between S and E (S < X < E) *only* in these cases:
//             //
//             // 0 |-------------X-----E----S----------------|    (wraparound)
//             //
//             // but not in if S < E < X
//             //
//             if end < start && end > x {
//                 return true;
//             } else {
//                 return false;
//             }
//         }
//     }
// }


fn print_connection(c: &Connection) {

    match  c.state {
        State::SynRcvd => eprintln!("State:\tSynRcvd"),
        State::Estab => eprintln!("State:\tEstab"),
        State::FinWait1 => eprintln!("State:\tFinWait1"),
        State::FinWait2 => eprintln!("State:\tFinWait2"),
        State::Closing => eprintln!("State:\tClosing"),
        State::TimeWait => eprintln!("State:\tTimeWait"),
        
    }

    eprintln!("SendSequenceSpace:\t iss: {}\t una: {}\t ntx {}\t wnd: {}\t up: {}", c.send.iss, c.send.una, c.send.nxt, c.send.wnd, c.send.up);
    eprintln!("RecvSequenceSpace:\t irs: {}\t nxt: {}\t wnd: {}\t up: {}", c.recv.irs, c.recv.nxt, c.recv.wnd , c.recv.up);
}