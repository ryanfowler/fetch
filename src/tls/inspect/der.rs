#[derive(Clone, Copy)]
pub(super) struct Tlv<'a> {
    pub(super) tag: u8,
    pub(super) value: &'a [u8],
    pub(super) raw: &'a [u8],
}

pub(super) struct DerReader<'a> {
    data: &'a [u8],
}

impl<'a> DerReader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(super) fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    pub(super) fn read_tlv(&mut self) -> Option<Tlv<'a>> {
        if self.data.len() < 2 {
            return None;
        }
        let original = self.data;
        let tag = self.data[0];
        let first_len = self.data[1];
        let mut offset = 2;
        let len = if first_len & 0x80 == 0 {
            usize::from(first_len)
        } else {
            let count = usize::from(first_len & 0x7f);
            if count == 0 || count > 4 || self.data.len() < offset + count {
                return None;
            }
            let mut len = 0_usize;
            for byte in &self.data[offset..offset + count] {
                len = (len << 8) | usize::from(*byte);
            }
            offset += count;
            len
        };
        if self.data.len() < offset + len {
            return None;
        }
        let value = &self.data[offset..offset + len];
        self.data = &self.data[offset + len..];
        Some(Tlv {
            tag,
            value,
            raw: &original[..offset + len],
        })
    }
}
