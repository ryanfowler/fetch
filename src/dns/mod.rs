use std::net::IpAddr;

pub(crate) mod custom;
pub mod doh;
pub(crate) mod error;
pub mod inspect;
pub mod resolver;
pub(crate) mod svcb;
pub(crate) mod transport;
pub(crate) mod util;
pub(crate) mod wire;

pub(crate) fn ordered_unique_ip_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut unique = Vec::new();
    for addr in addrs {
        if !unique.contains(&addr) {
            unique.push(addr);
        }
    }
    unique
}
