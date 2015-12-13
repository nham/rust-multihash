extern crate openssl;
extern crate rust_base58;
extern crate rustc_serialize;

use self::HashType::*;

use openssl::crypto::hash as openssl_hash;
use rust_base58::{FromBase58, ToBase58};

#[derive(Copy, Clone)]
pub enum HashType {
    SHA1 = 0x11,
    SHA2_256 = 0x12,
    SHA2_512 = 0x13,
    SHA3 = 0x14,
    BLAKE2B = 0x40,
    BLAKE2S = 0x41,
}

impl HashType {
    pub fn from_code(code: u8) -> Option<HashType> {
        match code {
            0x11 => Some(SHA1),
            0x12 => Some(SHA2_256),
            0x13 => Some(SHA2_512),
            0x14 => Some(SHA3),
            0x40 => Some(BLAKE2B),
            0x41 => Some(BLAKE2S),
            _ => None,
        }
    }

    fn digest_len(&self) -> u8 {
        match *self {
            SHA1     => 20,
            SHA2_256 => 32,
            SHA2_512 => 64,
            SHA3     => 64,
            BLAKE2B  => 64,
            BLAKE2S  => 32,
        }
    }

    fn code(&self) -> u8 {
        *self as u8
    }

    fn to_str(&self) -> &'static str {
        match *self {
            SHA1     => "sha1",
            SHA2_256 => "sha2-256",
            SHA2_512 => "sha2-512",
            SHA3     => "sha3",
            BLAKE2B  => "blake2b",
            BLAKE2S  => "blake2s",
        }
    }
}

/// Hashes the `data` with the function described by `hash_type` and returns the result
/// as a Multihash.
pub fn multihash<'a>(data: &'a[u8], hash_type: HashType) -> Multihash {
    let openssl_type: openssl_hash::Type = match hash_type {
        SHA1     => openssl_hash::Type::SHA1,
        SHA2_256 => openssl_hash::Type::SHA256,
        SHA2_512 => openssl_hash::Type::SHA512,
        _ => panic!("That hash function is not yet implemented. Sorry"),
    };

    let hashed = openssl_hash::hash(openssl_type, data);

    Multihash::encode(&hashed[..], hash_type.code()).unwrap()
}


#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Multihash {
    bytes: Vec<u8>
}

impl Multihash {
    /// Construct a multihash from a base58 string by parsing it into bytes. Verifies
    /// that the bytes are valid according to the Multihash format.
    pub fn from_base58_str(s: &str) -> Result<Multihash, String> {
        let bytes = try!(s.from_base58()
                          .map_err(|e| format!("Error parsing base58 string: {}", e)));

        let hash_code = bytes[0];

        if !is_valid_code(hash_code) {
            return Err(format!("Invalid hash function code: {}", hash_code));
        }

        if !is_app_code(hash_code) {
            let hash_type = HashType::from_code(hash_code).unwrap();
            let expected_digest_len = hash_type.digest_len();
            if expected_digest_len != bytes[1] {
                return Err(format!("For hash function {}, expected digest length {}, but \
                                    found digest length {}", hash_type.to_str(),
                                    expected_digest_len, bytes[1]));
            }
        }

        if (bytes.len() - 2) as u8 != bytes[1] {
            return Err(format!("Hash digest is {} bytes, which does not match the stated \
                                digest length {}", bytes.len() - 2, bytes[1]));
        }

        Ok(Multihash::from_vec(bytes))
    }

    /// Create a Multihash directly from a vector of bytes. Does not verify that the
    /// bytes are a valid Multihash.
    pub fn from_vec(vec: Vec<u8>) -> Multihash {
        Multihash { bytes: vec }
    }

    pub fn as_bytes(&self) -> &[u8] { &self.bytes[..] }

    pub fn into_bytes(self) -> Vec<u8> { self.bytes }

    /// Construct a Multihash out of the hash digest and hash function code
    pub fn encode<'a>(digest: &'a [u8], hash_code: u8) -> Result<Multihash, String> {
        let size = digest.len();
        if size > 127 {
            return Err("Digest length > 127 is currently not supported.".to_string())
        }

        if !is_valid_code(hash_code) {
            return Err(format!("Invalid hash function code: {}", hash_code));
        }

        let mut v = Vec::with_capacity(size + 2);
        v.push(hash_code);
        v.push(size as u8);
        v.extend(digest);
        Ok(Multihash::from_vec(v))
    }

    // TODO: evaluate whether this function makes sense
    /*
    pub fn decode<'a>(&'a self) -> Result<DecodedMultiHash<'a>, DecodeError> {
        let mhlen = self.bytes.len();
        if mhlen < 3 {
            return Err(DecodeError::TooShort);
        } else if mhlen > 129 {
            return Err(DecodeError::TooLong);
        } else {
            let digest_len = (mhlen - 2) as u8;
            if digest_len != self.bytes[1] {
                return Err(DecodeError::InvalidDigestLength(self.bytes[1], digest_len));
            }
        }

        let fn_code = match HashType::from_code(self.bytes[0]) {
            None => return Err(DecodeError::UnknownCode(self.bytes[0])),
            Some(code) => code,
        };

        let decoded = DecodedMultiHash {
            code: fn_code,
            name: fn_code.to_str(),
            length: self.bytes[1],
            digest: &self.bytes[2..],
        };
        Ok(decoded)

    }
    */

    pub fn to_base58_string(&self) -> String {
        self.bytes.to_base58()
    }
}

impl rustc_serialize::Encodable for Multihash {
    fn encode<S>(&self, s: &mut S) -> Result<(), S::Error> where
        S: rustc_serialize::Encoder
    {
        self.to_base58_string().encode(s)
    }
}

impl rustc_serialize::Decodable for Multihash {
    fn decode<D>(d: &mut D) -> Result<Multihash, D::Error> where
        D: rustc_serialize::Decoder
    {
        let s = try!(d.read_str());
        Multihash::from_base58_str(&s).map_err(|e| d.error(&e))
    }
}

impl rustc_serialize::hex::ToHex for Multihash {
    fn to_hex(&self) -> String {
        self.bytes.to_hex()
    }
}

fn is_valid_code(code: u8) -> bool {
    is_app_code(code) || HashType::from_code(code).is_some()
}

fn is_app_code(code: u8) -> bool {
    code <= 0x0f
}

/*
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
*/


#[cfg(test)]
mod tests {
    use super::{multihash, Multihash, HashType};
    use rustc_serialize::hex::FromHex;
    use rust_base58::ToBase58;

    struct TestCase {
        hexstr: &'static str,
        hash_type: HashType,
    }

    impl TestCase {
        fn new(s: &'static str, ty: HashType) -> TestCase {
            TestCase { hexstr: s, hash_type: ty }
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
        let abc = b"ABC";
        let sha1_hex = "3c01bdbb26f358bab27f267924aa2c9a03fcfdb8";
        let sha256_hex = "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78";
        let sha512_hex = "397118fdac8d83ad98813c50759c85b8c47565d8268bf10da483153b747a7474\
                          3a58a90e85aa9f705ce6984ffc128db567489817e4092d050d8a1cc596ddc119";

        let sha1 = multihash(abc, HashType::SHA1);
        let mut sha1_bytes = hexstr_to_vec(sha1_hex);
        let mut expected_bytes = vec![0x11, 20];
        expected_bytes.append(&mut sha1_bytes);
        assert_eq!(sha1.as_bytes(), &expected_bytes[..]);

        let sha256 = multihash(abc, HashType::SHA2_256);
        let mut sha256_bytes = hexstr_to_vec(sha256_hex);
        let mut expected_bytes = vec![0x12, 32];
        expected_bytes.append(&mut sha256_bytes);
        assert_eq!(sha256.as_bytes(), &expected_bytes[..]);


        let sha512 = multihash(abc, HashType::SHA2_512);
        let mut sha512_bytes = hexstr_to_vec(sha512_hex);
        let mut expected_bytes = vec![0x13, 64];
        expected_bytes.append(&mut sha512_bytes);
        assert_eq!(sha512.as_bytes(), &expected_bytes[..]);
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

            let mut expected = Vec::new();
            expected.push(case.hash_type.code());
            expected.push(v.len() as u8);
            expected.extend(&v[..]);

            let mh = Multihash::encode(&v[..], case.hash_type.code()).unwrap();
            assert_eq!(&expected[..], mh.as_bytes());
        }
    }

    /*
    #[test]
    fn test_decode() {
        let mut cases = Vec::new();

        cases.push(TestCase::new(SHA1_STR, HashType::SHA1));
        cases.push(TestCase::new(SHA256_STR, HashType::SHA2_256));
        cases.push(TestCase::new(SHA512_STR, HashType::SHA2_512));

        for case in cases {
            let v = hexstr_to_vec(case.hexstr);
            let digest_length = v.len() as u8;
            let mh = Multihash::encode(&v[..], case.hash_type).unwrap();
            let hash_name = case.hash_type.to_str();

            match mh.decode() {
                Err(e) => panic!("Error decoding: {:?}", e),
                Ok(decoded) => {
                    assert_eq!(decoded.code, case.hash_type);
                    assert_eq!(decoded.name, hash_name);
                    assert_eq!(decoded.length, digest_length);
                    assert_eq!(decoded.digest, &v[..]);
                },
            }
        }
    }
    */

    #[test]
    fn test_from_base58_str() {
        assert!(Multihash::from_base58_str("Invalid base58!!!").is_err());

        // digest length of SHA1 is 20, not 5
        let x = &[0x11, 5, 1, 2, 3, 4, 5];
        assert!(Multihash::from_base58_str(&x.to_base58()).is_err());

        // mismatch between stated digest length and actual digest length
        let x = &[0x11, 20, 1, 2, 3, 4, 5];
        assert!(Multihash::from_base58_str(&x.to_base58()).is_err());

        let x = &[0x11, 20, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                  0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(Multihash::from_base58_str(&x.to_base58()).is_ok());

        let x = "QmR6XorNYAywK4q1dRiRN1gmvfLcx3ccBv68iGtAqon9tt";
        assert!(Multihash::from_base58_str(x).is_ok());
    }
}
