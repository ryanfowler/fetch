use crate::proto::ProtoError;

pub(crate) fn reflected_file_name(file: &[u8]) -> Result<String, ProtoError> {
    let mut raw = file;
    while !raw.is_empty() {
        let (field, wire) = read_key(&mut raw)?;
        if field == 1 && wire == 2 {
            return read_len_string(&mut raw);
        }
        skip_wire_value(wire, &mut raw)?;
    }
    Err(ProtoError::Message(
        "reflected descriptor is missing a file name".to_string(),
    ))
}

fn read_key(raw: &mut &[u8]) -> Result<(u64, u8), ProtoError> {
    let key = read_varint(raw)?;
    Ok((key >> 3, (key & 0x07) as u8))
}

fn read_varint(raw: &mut &[u8]) -> Result<u64, ProtoError> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = raw.split_first() else {
            return Err(ProtoError::Message(
                "unexpected EOF while reading varint".to_string(),
            ));
        };
        *raw = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ProtoError::Message("varint overflows uint64".to_string()))
}

fn read_len_bytes(raw: &mut &[u8]) -> Result<Vec<u8>, ProtoError> {
    let len = usize::try_from(read_varint(raw)?)
        .map_err(|_| ProtoError::Message("length overflows usize".to_string()))?;
    if raw.len() < len {
        return Err(ProtoError::Message(
            "unexpected EOF while reading bytes".to_string(),
        ));
    }
    let out = raw[..len].to_vec();
    *raw = &raw[len..];
    Ok(out)
}

fn read_len_string(raw: &mut &[u8]) -> Result<String, ProtoError> {
    String::from_utf8(read_len_bytes(raw)?)
        .map_err(|err| ProtoError::Message(format!("invalid UTF-8 string: {err}")))
}

fn skip_wire_value(wire: u8, raw: &mut &[u8]) -> Result<(), ProtoError> {
    match wire {
        0 => {
            read_varint(raw)?;
        }
        1 => skip_fixed(raw, 8)?,
        2 => {
            let len = usize::try_from(read_varint(raw)?)
                .map_err(|_| ProtoError::Message("length overflows usize".to_string()))?;
            skip_fixed(raw, len)?;
        }
        5 => skip_fixed(raw, 4)?,
        _ => return Err(ProtoError::Message(format!("unsupported wire type {wire}"))),
    }
    Ok(())
}

fn skip_fixed(raw: &mut &[u8], len: usize) -> Result<(), ProtoError> {
    if raw.len() < len {
        return Err(ProtoError::Message(
            "unexpected EOF while skipping field".to_string(),
        ));
    }
    *raw = &raw[len..];
    Ok(())
}
