#![feature(collections)]

extern crate rust_base58;
extern crate openssl;
#[cfg(test)] extern crate rustc_serialize;

use rust_base58::ToBase58;
use self::HashType::*;

use openssl::crypto::hash as openssl_hash;

// https://github.com/jbenet/multihash
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HashType {
    SHA1 = 0x11,
    SHA2_256 = 0x12,
    SHA2_512 = 0x13,
    SHA3 = 0x14,
    BLAKE2B = 0x40,
    BLAKE2S = 0x41,
}

impl HashType {
    pub fn from_u8(x: u8) -> Option<HashType> {
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

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

// Takes bytes and a HashType, returns multihash of the bytes
pub fn multihash<'a>(data: &'a[u8], hash_type: HashType) -> Multihash {
    let mut openssl_type: openssl_hash::Type = match hash_type {
        SHA1 => openssl_hash::Type::SHA1,
        SHA2_256 => openssl_hash::Type::SHA256,
        SHA2_512 => openssl_hash::Type::SHA512,
        _ => panic!("That hash function is not yet implemented. Sorry"),
    };

    let mut hashed = openssl_hash::hash(openssl_type, data);

    Multihash::encode(&hashed[..], hash_type as u8).unwrap()
}


struct HashFnTypeData {
    name: &'static str,
    default_len: u8,
}


fn hashfn_data(hft: &HashType) -> HashFnTypeData {
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


pub struct Multihash(Vec<u8>);

impl Multihash {
    pub fn new() -> Multihash {
        Multihash(Vec::new())
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0
    }


    // Constructs a Multihash out of the bytes of a hash and the
    // HashFnCode corresponding to the type of hash function used
    pub fn encode<'a>(data: &'a [u8], code: u8) -> Result<Multihash, EncodeError> {
        match HashType::from_u8(code) {
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
        v.extend(data);
        Ok(Multihash(v))
    }

    pub fn decode<'a>(&'a self) -> Result<DecodedMultiHash<'a>, DecodeError> {
        let mhlen = self.0.len();
        if mhlen < 3 {
            return Err(DecodeError::TooShort);
        } else if mhlen > 129 {
            return Err(DecodeError::TooLong);
        } else {
            let digest_len = (mhlen - 2) as u8;
            if digest_len != self.0[1] {
                return Err(DecodeError::InvalidDigestLength(self.0[1], digest_len));
            }
        }

        let fn_code = match HashType::from_u8(self.0[0]) {
            None => return Err(DecodeError::UnknownCode(self.0[0])),
            Some(code) => code,
        };

        let hash_fn = hashfn_data(&fn_code);

        let decoded = DecodedMultiHash {
            code: fn_code,
            name: hash_fn.name,
            length: self.0[1],
            digest: &self.0[2..],
        };
        Ok(decoded)

    }

    pub fn to_base58_string(&self) -> String {
        self.0.to_base58()
    }
}


pub struct DecodedMultiHash<'a> {
    code: HashType,
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
    use super::{Multihash, HashType, DecodedMultiHash, multihash, hashfn_data};
    use rustc_serialize::hex::FromHex;

    struct TestCase {
        hexstr: &'static str,
        hash_fn_type: HashType,
    }

    impl TestCase {
        fn new(s: &'static str, ty: HashType) -> TestCase {
            TestCase { hexstr: s, hash_fn_type: ty }
        }
    }

    static SHA1_STR: &'static str = "a228821137dacdbcd3ba5fa264f918fd
                                     a6223f7b";

    static SHA256_STR: &'static str = "95071c8e1ad3c7a016b30fd25853c1d9\
                                       e346ee7ee4afc977f554b139f71f4f30";

    static SHA512_STR: &'static str = "3912d4c1777934091ed95a15278b351e\
                                       00efa51f524af9af3320f0f6a227d551\
                                       76b1399684d15a05f03d1e519a9a9aa5\
                                       2a812a6d9bc63e5b485d6fd7ebf72114";


    #[test]
    fn test_multihash() {
        multihash(b"ABC", HashType::SHA1);
        multihash(b"ABC", HashType::SHA2_256);
        multihash(b"ABC", HashType::SHA2_512);
    }

    fn hexstr_to_vec(hexstr: &'static str) -> Vec<u8> {
        match hexstr.from_hex() {
            Err(e) => panic!("from_hex() failed with error: {:?}", e),
            Ok(vec) => vec,
        }
    }

    #[test]
    fn test_encode() {
        let mut cases = Vec::new();

        cases.push(TestCase::new(SHA1_STR, HashType::SHA1));
        cases.push(TestCase::new(SHA256_STR, HashType::SHA2_256));
        cases.push(TestCase::new(SHA512_STR, HashType::SHA2_512));

        for case in cases {
            let v = hexstr_to_vec(case.hexstr);

            let mut manual = Vec::new();
            manual.push(case.hash_fn_type as u8);
            manual.push(v.len() as u8);
            manual.extend(&v[..]);

            let mh = Multihash::encode(&v[..], case.hash_fn_type as u8).unwrap();
            assert_eq!(manual, mh.to_vec());
        }
    }

    #[test]
    fn test_decode() {
        let mut cases = Vec::new();

        cases.push(TestCase::new(SHA1_STR, HashType::SHA1));
        cases.push(TestCase::new(SHA256_STR, HashType::SHA2_256));
        cases.push(TestCase::new(SHA512_STR, HashType::SHA2_512));

        for case in cases {
            let v = hexstr_to_vec(case.hexstr);
            let digest_length = v.len() as u8;
            let mh = Multihash::encode(&v[..], case.hash_fn_type as u8).unwrap();
            let hash_name = hashfn_data(&case.hash_fn_type).name;

            match mh.decode() {
                Err(e) => panic!("Error decoding: {:?}", e),
                Ok(decoded) => {
                    assert_eq!(decoded.code, case.hash_fn_type);
                    assert_eq!(decoded.name, hash_name);
                    assert_eq!(decoded.length, digest_length);
                    assert_eq!(decoded.digest, &v[..]);
                },
            }
        }
    }

}
