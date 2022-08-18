#![allow(warnings, unused)]

use std::io;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, Condvar};
use std::thread;
use std::collections::{HashMap, VecDeque};

use tcp::Available;

mod tcp;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct Foobar {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    receive_var: Condvar,
}

type InterfaceHandle = Arc<Foobar>;
pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
        self.jh
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}

#[derive(Default)]
struct Pending {
    quads: VecDeque<Quad>,
    var: Condvar,
}

#[derive(Default)]
pub struct ConnectionManager {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()>{
    let mut buf = [0u8; 1504];

    loop{
        // TODO: set timeout for this recv for TCP timers or ConnectionManager::terminate
        let nbytes = nic.recv(&mut buf[..])?;

        // TODO: if self.terminate && Arc::get_strong_refs(ih) == 1; then tear down all connections and return

        // we cannot use it since we are using tuntap mode: without_packet_info
        //
        // if s/without_package_info/new/:
        //
        // let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if(eth_proto != 0x0800){
        //     // not ipv4
        //     continue;
        // }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(ip_h) => {
                let ip_src = ip_h.source_addr();
                let ip_dst = ip_h.destination_addr();
                let ip_proto = ip_h.protocol();
                if(ip_proto != 0x06){
                    // not tcp 
                    continue;
                }

                let ip_hdr_sz = ip_h.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[ip_h.slice().len()..]){
                    Ok(tcp_h) => {
                        use std::collections::hash_map::Entry;
                        let datai = ip_hdr_sz + tcp_h.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let mut cm = &mut *cmg;
                        let q = Quad {
                            src: (ip_src, tcp_h.source_port()),
                            dst: (ip_dst, tcp_h.destination_port()),
                        };

                        match cm.connections.entry(q){
                            Entry::Occupied(mut c) => {

                                let a = c.get_mut().on_packet(
                                    &mut nic, 
                                    ip_h, 
                                    tcp_h, 
                                    &buf[datai..nbytes]
                                )?;

                                // TODO: compare before/after
                                drop(cmg);
                                if a.contains(tcp::Available::READ) {  
                                    ih.pending_var.notify_all()
                                }
                                if a.contains(tcp::Available::WRITE) {  
                                    // TODO: ih.send_var.notify_all()
                                }
                            }
                            Entry::Vacant( e) => {
                                if let Some(pending) = cm.pending.get_mut(&tcp_h.destination_port()) {
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic, 
                                        ip_h,
                                        tcp_h, 
                                        &buf[datai..nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);
                                        drop(cm);
                                        drop(cmg);
                                        ih.pending_var.notify_all();

                                        // TODO: wake up pending accept();
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird package {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird package {:?}", e);
            }
        }
    }
    Ok(())
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();
        let jh = {
            let ih = ih.clone();
            thread::spawn(move || {
                let nic = nic;
                let ih = ih;
                let buf = [0u8; 1504];

                packet_loop(nic ,ih)

                // TODO: do the stuff that main does
            })
        };

        Ok(Interface {
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();

        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already in bound",
                ));
            }
        };
        drop(cm);
        Ok(TcpListener{
            port, 
            h: self.ih.as_mut().unwrap().clone()
        })
    }
}

pub struct TcpListener {
    port: u16, 
    h: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) { 
        let mut cm = self.h.manager.lock().unwrap();
        let pending = cm.pending
        .remove(&self.port)
        .expect("port closed while listener still active");
        
        for quad in pending {
            // TODO: terminate cm.connections[quad]
            unimplemented!()
        }
     }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
            .pending
            .get_mut(&self.port)
            .expect("port closed while listener still active")
            .pop_front()
            { 
                return Ok(TcpStream{
                    quad, 
                    h: self.h.clone(),
                });
            }
            
            cm = self.h.pending_var.wait(cm).unwrap();
        }
    }
}

pub struct TcpStream{
    quad: Quad, 
    h: InterfaceHandle,
}

impl Drop for TcpStream {
    fn drop(&mut self) { 
        let mut cm = self.h.manager.lock().unwrap();
        // TODO: send FIN on cm.connections[quad]
        // TODO: _eventually_ remove self.quad from cm.connections
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();

        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated")
            })?;
    
            if c.is_rcv_closed() && c.incoming.is_empty() {
                // no more data to read, and no need to block, because there wont be any more
                return Ok(0);
            }
    
            if !c.incoming.is_empty() {
                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();
                let mut hread = std::cmp::min(buf.len(), head.len());
                buf.copy_from_slice(&head[..hread]);
                nread += hread;
                let mut tread = std::cmp::min(buf.len() - nread, head.len());
                buf.copy_from_slice(&tail[..tread]);
                nread += tread;
                drop(c.incoming.drain(..nread));
                return Ok(nread);
            }
    
            cm = self.h.receive_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated")
        })?;

        if c.unacked.len() >= SENDQUEUE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(buf[..nwrite].iter());

        // TODO: wake up writer

        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated")
        })?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ))
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        // TODO: send FIN on cm.connections[quad]
        unimplemented!()
    }
}
