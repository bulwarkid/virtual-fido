use std::net::{TcpListener, TcpStream};
use std::io::Read;

fn handle_client(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let mut data = [0; 4];
    let mut bytes_read = stream.read(&mut data)?;
    while bytes_read > 0 {
        println!("{:?}", data);
        bytes_read = stream.read(&mut data)?;
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    println!("Starting server...");
    let listener = TcpListener::bind("127.0.0.1:3240")?;

    for stream in listener.incoming() {
        handle_client(&mut stream?)?;
    }

    Ok(())
}
