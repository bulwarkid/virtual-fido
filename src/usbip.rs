use std::net::TcpStream;
use std::io::Read;

#[derive(Debug)]
pub struct USBIPHeader {
    version: u16,
    command_code: u16,
    status: u32,
}

pub fn read_usbip_header(stream: &mut TcpStream) -> std::io::Result<USBIPHeader> {
    let mut data: [u8; 8] = [0; 8];
    stream.read(&mut data)?;
    let version = u16::from_be_bytes(data[0..2].try_into().expect("Wrong bytes length"));
    let command_code = u16::from_be_bytes(data[2..4].try_into().expect("Wrong bytes length"));
    let status = u32::from_be_bytes(data[4..8].try_into().expect("Wrong bytes length"));
    Ok(USBIPHeader{version, command_code, status})
}