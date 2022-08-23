use crate::{Decodable, Encodable};
use minimint_api::encoding::DecodeError;
use schnorr_fun::{
    frost::{Frost, PointPoly},
    fun::marker::{Mark, Public, Zero},
    nonce::Deterministic,
};

pub use schnorr_fun::binonce::Nonce;
pub use schnorr_fun::frost::FrostKey;
pub use schnorr_fun::frost::SignSession;
pub use schnorr_fun::frost::XOnlyFrostKey;
pub use schnorr_fun::fun::marker::EvenY;
pub use schnorr_fun::fun::Point;
pub use schnorr_fun::fun::Scalar;
pub use schnorr_fun::Message;
pub use schnorr_fun::Schnorr;
pub use schnorr_fun::Signature;

use serde::{Deserialize, Serialize};
pub use sha2::Sha256;

pub type VerificationShare = Point;

#[derive(Clone, Debug, Eq, Serialize, PartialEq, Hash, Deserialize)]
pub struct FrostNonce(pub Nonce);

impl Encodable for FrostNonce {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        writer.write(&self.0.to_bytes())
    }
}

impl Decodable for FrostNonce {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut nonce_bytes = [0u8; 66];
        d.read_exact(&mut nonce_bytes)
            .map_err(DecodeError::from_err)?;
        let nonce = Nonce::from_bytes(nonce_bytes)
            .ok_or(DecodeError::from_str("Invalid 66 byte binonce"))?;
        Ok(FrostNonce(nonce))
    }
}

#[derive(Clone, Copy, Debug, Eq, Serialize, PartialEq, Hash, Deserialize)]
pub struct FrostSigShare(pub Scalar<Public, Zero>);

impl Encodable for FrostSigShare {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        writer.write(&self.0.to_bytes())
    }
}

impl Decodable for FrostSigShare {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let mut scalar_bytes = [0u8; 32];
        d.read_exact(&mut scalar_bytes)
            .map_err(DecodeError::from_err)?;
        let scalar =
            Scalar::from_bytes(scalar_bytes).ok_or(DecodeError::from_str("Invalid scalar"))?;
        Ok(FrostSigShare(scalar.mark::<Public>()))
    }
}

pub fn new_frost() -> Frost<Sha256, Deterministic<Sha256>> {
    Frost::default()
}

pub fn trusted_frost_gen(
    threshold: u32,
    n_parties: u32,
    // _rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<Scalar>, FrostKey) {
    let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
        Deterministic::<Sha256>::default(),
    ));

    // create some scalar poly for each party
    let mut scalar_polys = vec![];
    for _ in 1..=n_parties {
        let scalar_poly = frost.new_scalar_poly(
            Scalar::random(&mut rand_2::thread_rng()),
            threshold,
            b"frost-minimint",
        );
        scalar_polys.push(scalar_poly);
    }
    let point_polys: Vec<PointPoly> = scalar_polys.iter().map(|sp| sp.to_point_poly()).collect();

    let key_gen = frost.new_keygen(point_polys).unwrap();

    let mut proofs_of_possession = vec![];
    let mut shares_vec = vec![];
    for sp in scalar_polys.into_iter() {
        let (shares, pop) = frost.create_shares(&key_gen, sp);
        proofs_of_possession.push(pop);
        shares_vec.push(shares);
    }

    // TODO nice transpose
    let (secret_shares, frost_keys): (Vec<_>, Vec<_>) = (0..n_parties)
        .map(|reciever_index| {
            let recieved_shares = (0..n_parties)
                .map(|sender_index| {
                    shares_vec[sender_index as usize][reciever_index as usize].clone()
                })
                .collect();

            let (secret_share, frost_key) = frost
                .finish_keygen(
                    key_gen.clone(),
                    reciever_index as u32,
                    recieved_shares,
                    proofs_of_possession.clone(),
                )
                .unwrap();
            (secret_share, frost_key)
        })
        .unzip();

    (secret_shares, frost_keys[0].clone())
}
