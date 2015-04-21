use self::HashFnCode::*;

pub struct DecodedMultiHash<'a> {
    code: HashFnCode,
    name: &'static str,
    length: u8,
    digest: &'a [u8],
}

pub struct VecMultiHash {
    vec: Vec<u8>,
}

impl VecMultiHash {
    pub fn new() -> VecMultiHash {
        VecMultiHash { vec: Vec::new() }
    }

    pub fn from(v: Vec<u8>) -> VecMultiHash {
        VecMultiHash { vec: v }
    }

    pub fn encode(data: Vec<u8>, code: HashFnCode) -> Result<VecMultiHash, EncodeError> {
        let size = data.len();
        if size > 127 {
            return Err(EncodeError::NotSupported(size));
        }

        let mut v = Vec::with_capacity(size + 2);
        v[0] = code as u8;
        v[1] = size as u8;
        // copy rest of data in
        Ok(VecMultiHash::from(v))
    }

    pub fn decode<'a>(&'a self) -> Result<DecodedMultiHash<'a>, DecodeError> {
        let mhlen = self.vec.len();
        if mhlen < 3 {
            return Err(DecodeError::TooShort);
        } else if mhlen > 129 {
            return Err(DecodeError::TooLong);
        } else {
            let digest_len = (mhlen - 2) as u8;
            if digest_len != self.vec[1] {
                return Err(DecodeError::InvalidDigestLength(self.vec[1], digest_len));
            }
        }

        let fn_code = match HashFnCode::from(self.vec[0]) {
            None => return Err(DecodeError::UnknownCode(self.vec[0])),
            Some(code) => code,
        };

        let hash_fn = hashfn_data(&fn_code);

        let decoded = DecodedMultiHash {
            code: fn_code,
            name: hash_fn.name,
            length: self.vec[1],
            digest: &self.vec[2..],
        };
        Ok(decoded)

    }
}

// https://github.com/jbenet/multihash
pub enum HashFnCode {
    Sha1 = 0x11,
    Sha2_256 = 0x12,
    Sha2_512 = 0x13,
    Sha3 = 0x14,
    Blake2b = 0x40,
    Blake2s = 0x41,
}

impl HashFnCode {
    pub fn from(x: u8) -> Option<HashFnCode> {
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

pub enum DecodeError {
    UnknownCode(u8),
    TooShort,
    TooLong,
    InvalidDigestLength(u8, u8), // (stated, actual)
}

pub enum EncodeError {
    UnknownCode(u8),
    NotSupported(usize),
}





struct HashFnTypeData {
    name: &'static str,
    default_len: u8,
}


fn hashfn_data(hft: &HashFnCode) -> HashFnTypeData {
    match *hft {
        Sha1 =>
            HashFnTypeData { name: "sha1", default_len: 20 },

        Sha2_256 =>
            HashFnTypeData { name: "sha2-256", default_len: 32 },

        Sha2_512 =>
            HashFnTypeData { name: "sha2-512", default_len: 64 },

        Sha3 =>
            HashFnTypeData { name: "sha3", default_len: 64 },

        Blake2b =>
            HashFnTypeData { name: "blake2b", default_len: 64 },

        Blake2s =>
            HashFnTypeData { name: "blake2s", default_len: 32 },
    }
}
