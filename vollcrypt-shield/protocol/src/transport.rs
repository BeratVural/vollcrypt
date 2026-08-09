use std::io::{Read, Write};

use minicbor::{Decode, Encode};

use crate::{ProtocolError, Result};

pub const MAX_PAIRING_FRAME_BYTES: usize = 65_536;

pub fn write_cbor_frame<T: Encode<()>>(writer: &mut impl Write, value: T) -> Result<()> {
    let encoded =
        minicbor::to_vec(value).map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    if encoded.is_empty() || encoded.len() > MAX_PAIRING_FRAME_BYTES {
        return Err(ProtocolError::InvalidPairing(
            "pairing frame exceeds size limit".to_owned(),
        ));
    }
    writer
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
    writer
        .write_all(&encoded)
        .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
    writer
        .flush()
        .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
    Ok(())
}

pub fn read_cbor_frame<T>(reader: &mut impl Read) -> Result<T>
where
    for<'bytes> T: Decode<'bytes, ()>,
{
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PAIRING_FRAME_BYTES {
        return Err(ProtocolError::InvalidPairing(
            "invalid pairing frame length".to_owned(),
        ));
    }
    let mut encoded = vec![0_u8; length];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| ProtocolError::InvalidPairing(error.to_string()))?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    let value = decoder
        .decode::<T>()
        .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    if decoder.position() != encoded.len() {
        return Err(ProtocolError::Serialization(
            "trailing bytes after pairing frame".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_round_trip_has_no_trailing_data() {
        let mut encoded = Vec::new();
        write_cbor_frame(&mut encoded, vec![1_u8, 2, 3]).unwrap();
        let decoded: Vec<u8> = read_cbor_frame(&mut Cursor::new(encoded)).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn oversized_and_ambiguous_frames_are_rejected() {
        let mut oversized = Vec::new();
        assert!(write_cbor_frame(&mut oversized, vec![0_u8; MAX_PAIRING_FRAME_BYTES]).is_err());

        let mut invalid_length = Cursor::new(((MAX_PAIRING_FRAME_BYTES as u32) + 1).to_be_bytes());
        assert!(read_cbor_frame::<u8>(&mut invalid_length).is_err());

        let mut trailing = Cursor::new(vec![0, 0, 0, 2, 1, 2]);
        assert!(read_cbor_frame::<u8>(&mut trailing).is_err());
    }
}
