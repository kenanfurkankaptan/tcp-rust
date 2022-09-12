use std::io::{Read, Write};
use std::prelude::*;
use std::{io, thread};

fn main() -> io::Result<()> {
    
    let mut i = tcpRust::Interface::new()?;
    let mut l = i.bind(9000)?;
    let jh = thread::spawn(move || {
        while let Ok(mut stream) = l.accept() {
            eprintln!("got connection on 9000!!");
            // stream.write(b"hello").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
           loop {
                let mut buf = [0; 512];

                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);

                if n == 0 {
                    eprintln!("no more data");
                    break;
                }
                else {
                    eprintln!("got {:?}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        }
    });

    jh.join().unwrap();
    Ok(())
}
