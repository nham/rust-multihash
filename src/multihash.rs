use phf;

static NAMES: phf::Map<&'static str, u8> = phf_map! {
    "sha1"     => 0x11,
    "sha2-256" => 0x12,
    "sha2-512" => 0x13,
    "sha3"     => 0x14,
    "blake2b"  => 0x40,
    "blake2s"  => 0x41,
};

static CODES: phf::Map<u8, &'static str> = phf_map! {
    0x11u8 => "sha1",
    0x12u8 => "sha2-256",
    0x13u8 => "sha2-512",
    0x14u8 => "sha3",
    0x40u8 => "blake2b",
    0x41u8 => "blake2s",
};

static DEFAULT_LENGTHS: phf::Map<u8, u8> = phf_map! {
    0x11u8 => 20,
    0x12u8 => 32,
    0x13u8 => 64,
    0x14u8 => 64,
    0x40u8 => 64,
    0x41u8 => 32,
};

struct DecodedMultihash<'a> {
    code: u8,
    name: &'static str,
    length: u8,
    digest: &'a [u8]
}

enum DecodeError {
    UnknownCode(u8),
    TooShort,
    TooLong,
    InvalidDigestLength(u8, u8), // (stated, actual)
}

enum EncodeError {
    UnknownCode(u8),
    NotSupported(usize),
}


fn decode<'a>(mh: &'a [u8]) -> Result<DecodedMultihash<'a>, DecodeError> {
    if mh.len() < 3 {
        return Err(DecodeError::TooShort);
    } else if mh.len() > 129 {
        return Err(DecodeError::TooLong);
    } else {
        let digest_len = (mh.len() - 2) as u8;
        if digest_len != mh[1] {
            return Err(DecodeError::InvalidDigestLength(mh[1], digest_len));
        }
    }

    let hash_fn_name = match CODES.get(&mh[0]) {
        None => return Err(DecodeError::UnknownCode(mh[0])),
        Some(c) => c,
    };

    let decoded = DecodedMultihash {
        code: mh[0],
        name: hash_fn_name,
        length: mh[1],
        digest: &mh[2..],
    };
    Ok(decoded)
}

fn encode<'a>(digest: &'a [u8], code: u8) -> Result<Vec<u8>, EncodeError> {
    if CODES.get(&code).is_none() {
        return Err(EncodeError::UnknownCode(code));
    }

    if digest.len() > 127 {
        return Err(EncodeError::NotSupported(digest.len()));
    }

    let mut v = vec![code, digest.len() as u8];
    v.push_all(digest);
    Ok(v)
}
