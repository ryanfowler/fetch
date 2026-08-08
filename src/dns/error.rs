use std::fmt;

/// A DNS result category that callers can use without parsing display text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DnsErrorKind {
    NxDomain,
    NoData,
    ServFail,
    Refused,
    FormErr,
    NotImp,
    BadVers,
    BadSig,
    Truncated,
    Timeout,
    Malformed,
    OtherRcode(u16),
    Other,
}

impl DnsErrorKind {
    pub(crate) fn from_rcode(rcode: u16) -> Option<Self> {
        match rcode {
            0 => None,
            1 => Some(Self::FormErr),
            2 => Some(Self::ServFail),
            3 => Some(Self::NxDomain),
            4 => Some(Self::NotImp),
            5 => Some(Self::Refused),
            16 => Some(Self::BadVers),
            other => Some(Self::OtherRcode(other)),
        }
    }
}

impl fmt::Display for DnsErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NxDomain => "DNS name does not exist (NXDOMAIN)",
            Self::NoData => "DNS response contains no matching records (NODATA)",
            Self::ServFail => "DNS server failure (SERVFAIL)",
            Self::Refused => "DNS query was refused (REFUSED)",
            Self::FormErr => "DNS server reported a format error (FORMERR)",
            Self::NotImp => "DNS query is not implemented (NOTIMP)",
            Self::BadVers => "DNS server rejected the EDNS version (BADVERS)",
            Self::BadSig => "DNS signature validation failed (BADSIG)",
            Self::Truncated => "DNS response was truncated",
            Self::Timeout => "DNS lookup timed out",
            Self::Malformed => "malformed DNS response",
            Self::OtherRcode(code) => return write!(formatter, "DNS server returned RCODE {code}"),
            Self::Other => "DNS lookup failed",
        })
    }
}
