use anyhow::{Error, Result};
use byteorder::{ByteOrder, LittleEndian};
use cipher::{
    generic_array::{typenum::U32, GenericArray},
    BlockDecryptMut, BlockEncrypt, {KeyInit, KeyIvInit},
};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::File, io::Read};

fn open(source: &mut dyn Read, password: &str) -> Result<Vec<String>> {
    let mut data = vec![];
    source.read_to_end(&mut data)?;
    if data[0..4] != [0x03, 0xd9, 0xa2, 0x9a] {
        return Err(Error::msg("Invalid KDBX magic"));
    }
    if data[4..8] != [0x67, 0xfb, 0x4b, 0xb5] || data[10..12] != [0x03, 0x00] {
        return Err(Error::msg("Only KDBX version 3 is supported"));
    }
    let mut header = HashMap::new();
    let mut transform_rounds = None;
    let mut i = 12;
    loop {
        let index = data[i];
        let len = LittleEndian::read_u16(&data[i + 1..(i + 3)]) as usize;
        let buffer = &data[(i + 3)..(i + 3 + len)];
        i += 3 + len;
        match index {
            0 => break,
            1 => {}
            2 => {}
            3 => {}
            4 => drop(header.insert("master_seed", buffer.to_vec())),
            5 => drop(header.insert("transform_seed", buffer.to_vec())),
            6 => transform_rounds = Some(LittleEndian::read_u64(buffer)),
            7 => drop(header.insert("outer_iv", buffer.to_vec())),
            8 => {}
            9 => drop(header.insert("stream_start", buffer.to_vec())),
            10 => {}
            _ => return Err(Error::msg("Unexpected index")),
        };
    }
    let password_sha = sha256(&[password.as_bytes()]).to_vec();
    let key_elements: Vec<&[u8]> = vec![&password_sha];
    let composite_key = sha256(&key_elements);
    let mut key: Vec<GenericArray<u8, _>> = composite_key
        .chunks_exact(16)
        .map(|b| *GenericArray::from_slice(b))
        .collect();
    let transform_seed = header
        .get("transform_seed")
        .expect("Missing transform seed");
    let cipher = aes::Aes256Enc::new_from_slice(transform_seed)?;
    let transform_rounds = transform_rounds.expect("Missing transform rounds");
    for _ in 0..transform_rounds {
        cipher.encrypt_blocks(&mut key);
    }
    let transformed_key = sha256(&[&key[0], &key[1]]);
    let master_seed = header.get("master_seed").expect("Missing master seed");
    let master_key = sha256(&[master_seed, &transformed_key]);
    let outer_iv = header.get("outer_iv").expect("Missing outer IV");
    let mut cipher = cbc::Decryptor::<aes::Aes256Dec>::new_from_slices(&master_key, outer_iv)?;
    let payload = data[i..].to_vec();
    let mut payload_blocks: Vec<GenericArray<u8, _>> = payload
        .chunks_exact(16)
        .map(|b| *GenericArray::from_slice(b))
        .collect();
    cipher.decrypt_blocks_mut(&mut payload_blocks);
    let payload = payload_blocks.concat();
    let stream_start = header.get("stream_start").expect("Missing stream start");
    if &payload[0..stream_start.len()] != stream_start.as_slice() {
        return Err(Error::msg("Header stream starts incorrectly"));
    }
    let mut blocks = vec![];
    let mut pos = 32;
    loop {
        let hash = &payload[(pos + 4)..(pos + 36)];
        let len = LittleEndian::read_u32(&payload[(pos + 36)..(pos + 40)]) as usize;
        if len == 0 {
            break;
        }
        let compressed = &payload[(pos + 40)..(pos + 40 + len)];
        let expected = sha256(&[&compressed]);
        if hash != expected.as_slice() {
            return Err(Error::msg("Block hash is invalid"));
        }
        let mut decompressed = vec![];
        let mut decoder = GzDecoder::new(compressed);
        decoder.read_to_end(&mut decompressed)?;
        blocks.push(decompressed);
        pos += 40 + len;
    }
    let data = blocks
        .iter()
        .map(|b| String::from_utf8(b.clone()).unwrap())
        .collect();
    Ok(data)
}

fn sha256(elements: &[&[u8]]) -> GenericArray<u8, U32> {
    let mut digest = Sha256::new();
    for element in elements {
        digest.update(element);
    }
    digest.finalize()
}

fn main() -> Result<()> {
    let password = std::env::args().nth(1).expect("Password not provided");
    let path = std::env::args().nth(2).expect("Path not provided");
    let mut source = File::open(path)?;
    let xml = open(&mut source, &password)?;
    println!("{:#?}", xml);
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::{fs::File, path::Path};

    #[test]
    fn test_that_it_opens() -> Result<()> {
        let path = Path::new("db.kdbx");
        let xml = crate::open(&mut File::open(path)?, "password")?;
        assert_eq!(1, xml.len());
        Ok(())
    }
}
