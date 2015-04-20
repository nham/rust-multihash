use self::HashFnType::*;

pub type MultiHash<'a> = &'a [u8];

enum HashFnType {
    Sha1 = 0x11,
    Sha2_256 = 0x12,
    Sha2_512 = 0x13,
    Sha3 = 0x14,
    Blake2b = 0x40,
    Blake2s = 0x41,
}

struct HashFnTypeData {
    name: &'static str,
    default_len: u8,
}

impl HashFnType {
    fn from(x: u8) -> Option<HashFnType> {
        match x {
            0x11 => Some(Sha1),
            0x12 => Some(Sha2_256),
            0x13 => Some(Sha2_512),
            0x14 => Some(Sha3),
            0x40 => Some(Blake2b),
            0x41 => Some(Blake2s),
            _ => None,
        }
    }
}

fn hashfn_data(hft: Option<HashFnType>) -> Option<HashFnTypeData> {
    match hft {
        None => None,
        Some(c) => match c {
            Sha1 => Some(HashFnTypeData{
                            name: "sha1",
                            default_len: 20}),

            Sha2_256 => Some(HashFnTypeData{
                            name: "sha2-256",
                            default_len: 32}),

            Sha2_512 => Some(HashFnTypeData{
                            name: "sha2-512",
                            default_len: 64}),

            Sha3 => Some(HashFnTypeData{
                            name: "sha3",
                            default_len: 64}),

            Blake2b => Some(HashFnTypeData{
                            name: "blake2b",
                            default_len: 64}),

            Blake2s => Some(HashFnTypeData{
                            name: "blake2s",
                            default_len: 32}),
        },
    }
}


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

    let hash_fn = match hashfn_data(HashFnType::from(mh[0])) {
        None => return Err(DecodeError::UnknownCode(mh[0])),
        Some(c) => c,
    };

    let decoded = DecodedMultihash {
        code: mh[0],
        name: hash_fn.name,
        length: mh[1],
        digest: &mh[2..],
    };
    Ok(decoded)
}

fn encode<'a>(digest: &'a [u8], code: u8) -> Result<Vec<u8>, EncodeError> {
    if hashfn_data(HashFnType::from(code)).is_none() {
        return Err(EncodeError::UnknownCode(code));
    }

    if digest.len() > 127 {
        return Err(EncodeError::NotSupported(digest.len()));
    }

    let mut v = vec![code, digest.len() as u8];
    v.push_all(digest);
    Ok(v)
}
