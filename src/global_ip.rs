// Copyright notice: This file includes a code from rust-lang/rust:
//   * File: https://github.com/rust-lang/rust/blob/1.56.1/library/std/src/net/ip.rs
//   * Original license: https://github.com/rust-lang/rust/blob/1.56.1/LICENSE-MIT

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

// FIXME: https://github.com/rust-lang/rust/issues/27709

pub const fn ipv4addr_is_global(a: &Ipv4Addr) -> bool {
    // https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml

    // While 192.0.0.0/24 is reserved for purpose without global reachability, .9/32 and .10/32 are
    // not:
    if u32::from_be_bytes(a.octets()) == 0xc0000009 || u32::from_be_bytes(a.octets()) == 0xc000000a
    {
        return true;
    }

    return a.octets()[0] != 0 && // 0.0.0.0/8
        !a.is_unspecified() &&
        !a.is_private() &&
        !(a.octets()[0] == 100 && (a.octets()[1] & 0b1100_0000 == 0b0100_0000)) && // 100.64.0.0/10
        !(a.octets()[0] == 169 && a.octets()[1] == 254) && // 169.254.0.0/16
        !(a.octets()[0] == 192 && a.octets()[1] == 0 && a.octets()[2] == 0) && // 192.0.0.0/24
        !a.is_documentation() &&
        !(a.octets()[0] == 198 && (a.octets()[1] & 0xfe) == 18) && // 198.18.0.0/15
        !(a.octets()[0] & 240 == 240 && !a.is_broadcast()) && // 240.0.0.0/4
        !a.is_broadcast() &&
        !a.is_loopback();
}

pub const fn ipv6addr_is_global(a: &Ipv6Addr) -> bool {
    // 2000::/3 (https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml)
    let f = a.octets()[0] & 0b11100000;
    return f == 0x20 || f == 0x30;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_global() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(1, 1, 1, 1)), true);
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(8, 8, 8, 8)), true);
    }

    #[test]
    fn test_ipv4_protocol_assignments_global() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(192, 0, 0, 9)), true);
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(192, 0, 0, 10)), true);
    }

    #[test]
    fn test_ipv4_rfc791_3_2() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(0, 0, 0, 1)), false);
    }

    #[test]
    fn test_ipv4_rfc1122_3_2_1_3() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(0, 0, 0, 0)), false);
    }

    #[test]
    fn test_ipv4_private() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(10, 200, 0, 1)), false);
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(172, 17, 0, 1)), false);
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(192, 168, 100, 1)), false);
    }

    #[test]
    fn test_ipv4_rfc6598() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(100, 65, 100, 65)), false);
    }

    #[test]
    fn test_ipv4_link_local() {
        assert_eq!(
            ipv4addr_is_global(&Ipv4Addr::new(169, 254, 169, 254)),
            false
        );
    }

    #[test]
    fn test_ipv4_documentation() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(192, 0, 2, 10)), false);
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(198, 51, 100, 20)), false);
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(203, 0, 113, 30)), false);
    }

    #[test]
    fn test_ipv4_benchmarking() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(198, 19, 198, 19)), false);
    }

    #[test]
    fn test_ipv4_reserved() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(240, 0, 0, 1)), false);
        assert_eq!(
            ipv4addr_is_global(&Ipv4Addr::new(243, 243, 243, 243)),
            false
        );
    }

    #[test]
    fn test_ipv4_broadcast() {
        assert_eq!(
            ipv4addr_is_global(&Ipv4Addr::new(255, 255, 255, 255)),
            false
        );
    }

    #[test]
    fn test_ipv4_loopback() {
        assert_eq!(ipv4addr_is_global(&Ipv4Addr::new(127, 0, 0, 1)), false);
        assert_eq!(
            ipv4addr_is_global(&Ipv4Addr::new(127, 127, 127, 127)),
            false
        );
    }

    #[test]
    fn test_ipv6_global() {
        assert_eq!(
            ipv6addr_is_global(&"2001:4860:4860::8888".parse().unwrap()),
            true
        );
        assert_eq!(
            ipv6addr_is_global(&"2606:4700:4700::1111".parse().unwrap()),
            true
        );
    }

    #[test]
    fn test_ipv6_ula() {
        assert_eq!(ipv6addr_is_global(&"fd00:ec2::254".parse().unwrap()), false);
    }

    #[test]
    fn test_ipv6_loopback() {
        assert_eq!(ipv6addr_is_global(&"::1".parse().unwrap()), false);
    }
}
