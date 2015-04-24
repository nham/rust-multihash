use rust_base58::ToBase58;
use self::HashFnType::*;

use openssl::crypto::hash as openssl_hash;


// https://github.com/jbenet/multihash
pub enum HashFnType {
    SHA1 = 0x11,
    SHA2_256 = 0x12,
    SHA2_512 = 0x13,
    SHA3 = 0x14,
    BLAKE2B = 0x40,
    BLAKE2S = 0x41,
}

impl HashFnType {
    pub fn from_u8(x: u8) -> Option<HashFnType> {
        match x {
            0x11 => Some(SHA1),
            0x12 => Some(SHA2_256),
            0x13 => Some(SHA2_512),
            0x14 => Some(SHA3),
            0x40 => Some(BLAKE2B),
            0x41 => Some(BLAKE2S),
            _ => None,
        }
    }
}

// Takes bytes and a HashFnType, returns hash of the bytes
pub fn multihash<'a>(data: &'a[u8], hash_type: HashFnType) -> VecMultiHash {
    let mut openssl_type: openssl_hash::Type = match hash_type {
        SHA1 => openssl_hash::Type::SHA1,
        SHA2_256 => openssl_hash::Type::SHA256,
        SHA2_512 => openssl_hash::Type::SHA512,
        _ => panic!("That hash function is not yet implemented. Sorry"),
    };

    let mut hashed = openssl_hash::hash(openssl_type, data);

    VecMultiHash::encode(&hashed[..], hash_type as u8).unwrap()
}


struct HashFnTypeData {
    name: &'static str,
    default_len: u8,
}


fn hashfn_data(hft: &HashFnType) -> HashFnTypeData {
    match *hft {
        SHA1 =>
            HashFnTypeData { name: "sha1", default_len: 20 },
        SHA2_256 =>
            HashFnTypeData { name: "sha2-256", default_len: 32 },
        SHA2_512 =>
            HashFnTypeData { name: "sha2-512", default_len: 64 },
        SHA3 =>
            HashFnTypeData { name: "sha3", default_len: 64 },
        BLAKE2B =>
            HashFnTypeData { name: "blake2b", default_len: 64 },
        BLAKE2S =>
            HashFnTypeData { name: "blake2s", default_len: 32 },
    }
}


pub struct VecMultiHash {
    vec: Vec<u8>,
}

impl VecMultiHash {
    pub fn new() -> VecMultiHash {
        VecMultiHash { vec: Vec::new() }
    }

    // For constructing a VecMultiHash directly from a vector.
    // Function assumes that first byte is hash function code,
    // second is digest length. It's up to you.
    pub fn from_vec(v: Vec<u8>) -> VecMultiHash {
        VecMultiHash { vec: v }
    }

    pub fn encode<'a>(data: &'a [u8], code: u8) -> Result<VecMultiHash, EncodeError> {
        match HashFnType::from_u8(code) {
            None => return Err(EncodeError::UnknownCode(code)),
            Some(_) => {},
        }

        let size = data.len();
        if size > 127 {
            return Err(EncodeError::NotSupported(size));
        }

        let mut v = Vec::with_capacity(size + 2);
        v.push(code);
        v.push(size as u8);
        v.push_all(data);
        Ok(VecMultiHash::from_vec(v))
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

        let fn_code = match HashFnType::from_u8(self.vec[0]) {
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

    pub fn vec(self) -> Vec<u8> {
        self.vec
    }

    pub fn to_base58_string(&self) -> String {
        self.vec.to_base58()
    }
}


pub struct DecodedMultiHash<'a> {
    code: HashFnType,
    name: &'static str,
    length: u8,
    digest: &'a [u8],
}

#[derive(Debug)]
pub enum DecodeError {
    UnknownCode(u8),
    TooShort,
    TooLong,
    InvalidDigestLength(u8, u8), // (stated, actual)
}

#[derive(Debug)]
pub enum EncodeError {
    UnknownCode(u8),
    NotSupported(usize),
}


#[cfg(test)]
mod tests {
    use multihash;

    #[test]
    fn test_hash() {
        multihash::hash(b"ABC", multihash::HashFnType::SHA1);
    }

}
