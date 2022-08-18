use std::io::Read;
use std::{io, thread};
use std::prelude::*;


fn main() -> io::Result<()> {
    
    let mut i = tcpRust::Interface::new()?;
    let mut l = i.bind(9000)?;
    let jh = thread::spawn(move || {
        while let Ok(mut _stream) = l.accept() {
            eprintln!("got connection on 9000!!");

            let n = _stream.read(&mut [0]).unwrap();
            eprintln!("read data");
            assert_eq!(n, 0);
        }

    });

    jh.join().unwrap();
    Ok(())
}
