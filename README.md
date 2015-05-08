# pcapng

A parser for the pcapng file format. It currently parses files exported by Wireshark.

# Example

Reading raw blocks:

```rust
extern crate pcapng;

use std::fs::File;
use pcapng::Block;

fn main() {
    let mut f = File::open("data.pcapng").unwrap();
    let mut r = pcapng::SimpleReader::new(&mut f);

    for block in r.blocks() {
        match block {
            Block::SectionHeader(h) => println!("Section {}", h),
            Block::InterfaceDescription(iface) => println!("Interface {}", iface),
            _ => {},
        }
    }
}

```

Parsing packets with [libpnet](https://github.com/libpnet/libpnet):

```rust
extern crate pcapng;
extern crate pnet;

use std::fs::File;
use pnet::packet::ethernet::EthernetPacket;

fn main() {
    let mut f = File::open("data.pcapng").unwrap();
    let mut r = pcapng::SimpleReader::new(&mut f);

    for (iface, ref packet) in r.packets() {
        // Ethernet only
        if iface.link_type != 1 {
            continue
        }

        let eh = EthernetPacket::new(&packet.data[..]);

        println!("Ethernet: {} -> {}", eh.get_source(), eh.get_destination());
    }
}


```

## Usage
To use `pcapng` in your project, add the following to your Cargo.toml:

```
[dependencies.pcapng]
git = "https://github.com/kornholi/pcapng.git"
```
