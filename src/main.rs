mod usbip;

use std::net::{TcpListener, TcpStream};


fn handle_stream(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let usbip_header = usbip::read_usbip_header(stream)?;
    println!("USBIP Header: (0x{:04x},0x{:04x},0x{:08x})", usbip_header.version, usbip_header.command_code, usbip_header.status);
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
