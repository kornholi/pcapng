use std::convert::From;

use std::str::Utf8Error;
use std::string::FromUtf8Error;

use std::io;
use std::io::BufReader;
use std::net::IpAddr;

extern crate byteorder;

use byteorder::{LittleEndian, ByteOrder, ReadBytesExt};

#[derive(Debug)]
pub enum Error {
    UnexpectedEOF,
    Io(io::Error),
    FormatError(FormatError)
}

#[derive(Debug, Clone)]
pub enum FormatError {
    UnknownBlock(u32),
    UnknownOption(u16),
    Utf8Error(Utf8Error)
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<byteorder::Error> for Error {
    fn from(err: byteorder::Error) -> Error {
        match err {
            byteorder::Error::UnexpectedEOF => Error::UnexpectedEOF,
            byteorder::Error::Io(io_err) => Error::Io(io_err)
        }
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        Error::FormatError(FormatError::Utf8Error(err.utf8_error()))
    }
}

impl From<FormatError> for Error {
    fn from(err: FormatError) -> Error {
        Error::FormatError(err)
    }
}

#[derive(Debug)]
pub enum Block {
    SectionHeader(SectionHeaderBlock),
    InterfaceDescription(InterfaceDescriptionBlock),
    InterfaceStatistics(InterfaceStatisticsBlock),
    EnhancedPacket(EnhancedPacketBlock)
}

#[derive(Debug)]
pub struct SectionHeaderBlock {
    /// Magic number equal to 0x1A2B3C4D. This field can be used to detect
    /// sections saved on systems with different endianness.
    pub magic: u32,

    pub major_version: u16,
    pub minor_version: u16,

    /// Length in bytes of the following section excluding this block.
    ///
    /// This block can be used to skip the section for faster navigation in
    /// large files. Length of -1u64 means that the length is unspecified.
    pub section_length: u64,
    pub options: Vec<SectionHeaderOption>
}

#[derive(Debug)]
pub enum SectionHeaderOption {
    /// Comment associated with the current block
    Comment(String),

    /// Description of the hardware used to create this section
    Hardware(String),

    /// Name of the operating system used to create this section
    OS(String),

    /// Name of the application used to create this section
    UserApplication(String)
}

/// Block type 1 
#[derive(Debug)]
pub struct InterfaceDescriptionBlock {
    /// Link layer type of the interface
    pub link_type: u16,

    /// Maximum number of bytes stored from each packet
    pub snap_len: u32,

    pub options: Vec<InterfaceDescriptionOption>
}

#[derive(Debug)]
pub enum InterfaceDescriptionOption {
    /// Comment associated with the current block
    Comment(String),

    /// Name of the device used to capture data
    Name(String),

    /// Description of the device used to capture data
    Description(String),

    /// IPv4 interface address and netmask
    Ipv4Addr(u32, u32),

    /// IPv6 interface address and prefix length
    Ipv6Addr(IpAddr, u8),

    /// Hardware MAC address (48 bits)
    MacAddr(u64),

    /// Hardware EUI address
    EuiAddr(u64),

    /// Interface speed in bps
    Speed(u64),

    /// Resolution of timestamps.
    ///
    /// If the MSB is equal to zero, the remaining bits indicate the resolution
    /// as a negative power of 10 (e.g. 6 means microsecond resolution,
    /// timestamps are teh number of microseconds since 1/1/1970).
    ///
    /// If the MSB is equal to one, the remaining bits indicate the resolution
    /// as a negative power of 2 (e.g. 10 means 1/1024 of a second).
    ///
    /// If this options is not present, microsecond resolution is assumed.
    TsResolution(u8),

    /// Timezone for GMT support (?)
    Timezone(u32),

    /// The filter used to capture traffic. The first byte specifies the type
    /// of filter used (e.g. libpcap string, BPF bytecode, etc)
    Filter(u8, Vec<u8>),

    /// Operating system of the machine in which this interface is installed.
    /// This can be different from the Section Header Block if the capture
    /// was done remotely.
    OS(String),

    /// Length of Frame Check Sequence in bits for this interface. For link
    /// layers whose FCS length can change during time, the Packet Block
    /// flags be used.
    FcsLen(u8),

    /// Offset pf the timestamp in seconds 
    TsOffset(u64)
}

/// Block type 5
#[derive(Debug)]
pub struct InterfaceStatisticsBlock {
    pub interface_id: u32,
    pub timestamp: u64,

    pub options: Vec<InterfaceStatisticsOption>
}

#[derive(Debug)]
pub enum InterfaceStatisticsOption {
    /// Comment associated with the current block
    Comment(String),

    /// Time when capture started
    StartTime(u64),

    /// Time when capture ended
    EndTime(u64),

    /// Number of packets received from the physical interface
    Received(u64),

    /// Number of packets dropped by the interface due to the lack of resources
    Dropped(u64),
    
    /// Number of packets accepted by the filter
    FilterAccepted(u64),

    /// Number of packets dropped by the operating system
    OSDropped(u64),

    /// Number of packets delivered to the user starting. The value in this
    /// field can be different from 'Accepted - Dropped' because some packets
    /// could still be in the OS buffers when the capture ended.
    Delivered(u64)
}

#[derive(Debug)]
pub struct EnhancedPacketBlock {
    pub interface_id: u32,
    pub timestamp: u64,

    /// Actual length of the packet when it was transmitted on the network
    pub len: u32,

    pub data: Vec<u8>,
    pub options: Vec<EnhancedPacketBlockOption>
}

#[derive(Debug)]
pub enum EnhancedPacketBlockOption {
    Comment(String),
    Flags(u32),
    Hash,

    /// Number of packets lost between the last packet
    DropCount(u64)
}

#[inline(always)]
fn dword_aligned(n: usize) -> usize {
    (n + 3) & !3
}

fn read_exact(r: &mut io::Read, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(n);
    unsafe { buf.set_len(n); }

    let mut i = 0;
    while i < n {
        i += try!(r.read(&mut buf[i..]));
    }

    Ok(buf)
}

pub fn read_raw_block<BO: ByteOrder>(r: &mut io::Read) -> Result<(u32, Vec<u8>), io::Error> {
    let block_type = try!(r.read_u32::<BO>());

    let total_len = try!(r.read_u32::<BO>()) as usize;
    let data_len = total_len - 12; // 12 = type + 2*length

    let mut data = try!(read_exact(r, dword_aligned(data_len)));
    data.truncate(data_len);

    assert!(total_len == try!(r.read_u32::<BO>()) as usize);

    Ok((block_type, data))
}

fn read_option<BO: ByteOrder>(r: &mut io::Read) -> Result<(u16, Vec<u8>), io::Error> {
    let code = try!(r.read_u16::<BO>());
    let len = try!(r.read_u16::<BO>()) as usize;

    let mut data = try!(read_exact(r, dword_aligned(len)));
    data.truncate(len);

    Ok((code, data))
}

pub fn read_block(r: &mut io::Read) -> Result<Block, Error> {
    use Block::*;
    type BO = LittleEndian;

    let (block_type, data) = try!(read_raw_block::<BO>(r));
    let mut r = BufReader::new(&data[..]);

    let r = match block_type {
        0x0A0D0D0A => SectionHeader(try!(SectionHeaderBlock::read::<BO>(&mut r))),
        1 => InterfaceDescription(try!(InterfaceDescriptionBlock::read::<BO>(&mut r))),
        5 => InterfaceStatistics(try!(InterfaceStatisticsBlock::read::<BO>(&mut r))),
        6 => EnhancedPacket(try!(EnhancedPacketBlock::read::<BO>(&mut r))),
        _ => return Err(From::from(FormatError::UnknownBlock(block_type)))
    };

    Ok(r)
}

pub struct BlockIter<'a> {
    r: &'a mut (io::Read + 'a)
}

pub struct PacketIter<'a> {
    r: &'a mut SimpleReader<'a>
}

pub struct SimpleReader<'a> {
    r: &'a mut (io::Read + 'a),

    interfaces: Vec<InterfaceDescriptionBlock>,
    if_offset: usize
}

impl<'a> Iterator for BlockIter<'a> {
    type Item = Block;

    fn next(&mut self) -> Option<Block> {
        match read_block(self.r) {
            Ok(block) => Some(block),
            Err(_) => None
        }
    }
}

pub type IterPacket<'a> = (&'a InterfaceDescriptionBlock, EnhancedPacketBlock);

impl<'a> Iterator for PacketIter<'a> {
    type Item = IterPacket<'a>;

    fn next(&mut self) -> Option<IterPacket<'a>> {
        while let Ok(block) = read_block(self.r.r) {
            match block {
                Block::SectionHeader(_) => {
                    // Each section is independent from another,
                    // however we might still have live references
                    // to the old interface descriptions so we
                    // can't just clear the vector
                    self.r.if_offset = self.r.interfaces.len()
                },

                Block::InterfaceDescription(id) => self.r.interfaces.push(id),

                Block::EnhancedPacket(ep) => {
                    let iface = &self.r.interfaces[self.r.if_offset + ep.interface_id as usize];
                    unsafe {
                        // The interface description should live as long as
                        // SimpleBufReader, so this should be safe.
                        let iface = std::mem::transmute(iface);
                    
                        return Some((iface, ep))
                    }
                },
                _ => {}
            }
        }

        None
    }
}

impl<'a> SimpleReader<'a> {
    pub fn new(r: &mut io::Read) -> SimpleReader {
        SimpleReader { r: r, interfaces: Vec::new(), if_offset: 0}
    }

    pub fn blocks(&mut self) -> BlockIter {
        BlockIter { r: self.r }
    }

    pub fn packets(&'a mut self) -> PacketIter<'a> {
        PacketIter { r: self }
    }
}

impl SectionHeaderBlock {
    pub fn read<BO: ByteOrder>(r: &mut io::Read) -> Result<SectionHeaderBlock, Error> {
        let magic = try!(r.read_u32::<BO>());
    
        assert!(magic == 0x1A2B3C4D, "unsupported endianness");

        let major_version = try!(r.read_u16::<BO>());
        let minor_version = try!(r.read_u16::<BO>());
        let section_length = try!(r.read_u64::<BO>());

        let mut options = Vec::new();

        loop {
            use SectionHeaderOption::*;

            let (code, data) = match read_option::<BO>(r) {
                Ok(x) => x,
                Err(_) => break
            };

            let opt = match code {
                0 => break,

                1...4 => {
                    let s = try!(String::from_utf8(data));

                    match code {
                        1 => Comment(s),
                        2 => Hardware(s),
                        3 => OS(s),
                        4 => UserApplication(s),
                        _ => unreachable!()
                    }
                }

                _ => return Err(From::from(FormatError::UnknownOption(code)))
            };

            options.push(opt);
        }

        Ok(SectionHeaderBlock {
            magic: magic,
            major_version: major_version,
            minor_version: minor_version,
            section_length: section_length,

            options: options
        })
    }
}

impl InterfaceDescriptionBlock {
    pub fn read<BO: ByteOrder>(r: &mut io::Read) -> Result<InterfaceDescriptionBlock, Error> {
        let link_type = try!(r.read_u16::<BO>());
        try!(r.read_u16::<BO>()); // Reserved
        let snap_len = try!(r.read_u32::<BO>());

        let mut options = Vec::new();

        loop {
            use InterfaceDescriptionOption::*;

            let (code, data) = match read_option::<BO>(r) {
                Ok(x) => x,
                Err(_) => break
            };

            let mut d = &data[..];

            let opt = match code {
                0 => break,
                1...3 | 12 => {
                    let s = try!(String::from_utf8(data.clone()));

                    match code {
                        1 => Comment(s),
                        2 => Name(s),
                        3 => Description(s),
                        12 => OS(s),
                        _ => unreachable!()
                    }
                }

                4 => {
                    let ip = try!(d.read_u32::<BO>());
                    let mask = try!(d.read_u32::<BO>());

                    Ipv4Addr(ip, mask)
                }

                6 => MacAddr(try!(d.read_uint::<BO>(6))),
                9 => TsResolution(try!(d.read_u8())),

                _ => return Err(From::from(FormatError::UnknownOption(code)))
            };

            options.push(opt);
        }

        Ok(InterfaceDescriptionBlock {
            link_type: link_type,
            snap_len: snap_len,
            options: options
        })
    }
}

impl EnhancedPacketBlock {
    pub fn read<BO: ByteOrder>(r: &mut io::Read) -> Result<EnhancedPacketBlock, Error> {
        let interface_id = try!(r.read_u32::<BO>());
        let ts = try!(r.read_u64::<BO>());
        let cap_len = try!(r.read_u32::<BO>()) as usize;
        let len = try!(r.read_u32::<BO>());

        let aligned_len = dword_aligned(cap_len);

        let mut packet_data = try!(read_exact(r, aligned_len));
        packet_data.truncate(cap_len);

        let mut options = Vec::new();

        loop {
            use EnhancedPacketBlockOption::*;

            let (code, data) = match read_option::<BO>(r) {
                Ok(x) => x,
                Err(_) => break
            };

            let opt = match code {
                0 => break,
                1 => {
                    match String::from_utf8(data.clone()) {
                        Ok(r) => Comment(r),
                        Err(err) => return Err(From::from(err))
                    }
                }

                // TODO: rest of the options
                _ => return Err(From::from(FormatError::UnknownOption(code)))
            };

            options.push(opt);
        }

        Ok(EnhancedPacketBlock {
            interface_id: interface_id,
            timestamp: ts,
            len: len,
            data: packet_data,
            options: options
        })
    }
}

impl InterfaceStatisticsBlock {
    pub fn read<BO: ByteOrder>(r: &mut io::Read) -> Result<InterfaceStatisticsBlock, Error> {
        let interface_id = try!(r.read_u32::<BO>());
        let ts = try!(r.read_u64::<BO>());

        let mut options = Vec::new();

        loop {
            use InterfaceStatisticsOption::*;

            let (code, data) = match read_option::<BO>(r) {
                Ok(x) => x,
                Err(_) => break
            };

            let opt = match code {
                0 => break,
                1 => {
                    match String::from_utf8(data.clone()) {
                        Ok(r) => Comment(r),
                        Err(err) => return Err(From::from(err))
                    }
                }

                2...8 => {
                    let data = try!((&*data).read_u64::<BO>());

                    match code {
                        2 => StartTime(data),
                        3 => EndTime(data),
                        4 => Received(data),
                        5 => Dropped(data),
                        6 => FilterAccepted(data),
                        7 => OSDropped(data),
                        8 => Delivered(data),
                        _ => unreachable!()
                    }
                }

                _ => return Err(From::from(FormatError::UnknownOption(code)))
            };

            options.push(opt);
        }

        Ok(InterfaceStatisticsBlock {
            interface_id: interface_id,
            timestamp: ts,
            options: options
        })
    }
}
