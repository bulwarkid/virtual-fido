mod usbip;

use std::net::{TcpListener, TcpStream};


fn handle_stream(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let usbip_header = usbip::read_usbip_header(stream)?;
    println!("{:?}", usbip_header);
    Ok(())
}

fn main() -> std::io::Result<()> {
    println!("Starting server...");
    let listener = TcpListener::bind("127.0.0.1:3240")?;

    for stream in listener.incoming() {
        handle_stream(&mut stream?)?;
    }

    Ok(())
}
