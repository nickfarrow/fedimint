use crate::encoding::{Decodable, DecodeError, Encodable};
use secp256kfun::g;
use secp256kfun::marker::Secret;
use secp256kfun::{
    marker::{Mark, NonZero, Public, Zero},
    Point, Scalar,
};

macro_rules! impl_external_encode_bls {
    ($ext:ident $(:: $ext_path:ident)*, $group:ty, $byte_len:expr) => {
        impl crate::encoding::Encodable for $ext $(:: $ext_path)* {
            fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
                let bytes = self.0.to_bytes();
                writer.write_all(&bytes)?;
                Ok(bytes.len())
            }
        }

        impl crate::encoding::Decodable for $ext $(:: $ext_path)* {
            fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, crate::encoding::DecodeError> {
                let mut bytes = [0u8; $byte_len];
                d.read_exact(&mut bytes).map_err(crate::encoding::DecodeError::from_err)?;
                let msg = <$group>::from_bytes_mod_order(bytes);
                Ok($ext $(:: $ext_path)*(msg.mark::<NonZero>().expect("surely")))
            }
        }
    }
}

impl_external_encode_bls!(tbs::BlindedMessage, Scalar<Secret, Zero>, 32);
impl_external_encode_bls!(tbs::BlindedSignatureShare, Scalar<Secret, Zero>, 32);
impl_external_encode_bls!(tbs::BlindedSignature, Scalar<Secret, Zero>, 32);
impl_external_encode_bls!(tbs::Signature, Scalar<Secret, Zero>, 32);

impl Encodable for tbs::BlindingKey {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for tbs::BlindingKey {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes).map_err(DecodeError::from_err)?;
        let key = Scalar::from_bytes(bytes);

        if key.is_some() {
            Ok(tbs::BlindingKey(
                key.unwrap().mark::<NonZero>().expect("pls be nonzerp"),
            ))
        } else {
            Err(crate::encoding::DecodeError::from_str(
                "Error decoding blinding key",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_roundtrip;
    use tbs::{BlindedMessage, BlindingKey};

    #[test_log::test]
    fn test_message_macro() {
        let bmsg = BlindedMessage(tbs::MessagePoint(g));
        test_roundtrip(bmsg);
    }

    #[test_log::test]
    fn test_bkey() {
        let bkey = BlindingKey::random();
        test_roundtrip(bkey);
    }
}
