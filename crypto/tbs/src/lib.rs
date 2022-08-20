mod serde_impl;
use core::num::NonZeroU32;

use rand::{rngs::OsRng, Rng};
use schnorr_fun::{
    frost::{Frost, FrostKey, PointPoly, ScalarPoly, SignSession},
    fun::marker::Public,
    nonce::Deterministic,
    Message, Schnorr,
};
use secp256kfun::{
    marker::{Mark, NonZero, Secret, Zero},
    s, Point, Scalar,
};
// use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug, PartialEq)]
pub struct MessageScalar(pub Scalar);

#[derive(Clone, Debug, PartialEq)]
pub struct BlindingKey(pub Scalar);

#[derive(Clone, Debug, PartialEq)]
pub struct BlindedMessage(pub Scalar);

#[derive(Clone, Debug, PartialEq)]
pub struct BlindedSignature(pub Scalar<Secret, NonZero>);

#[derive(Clone, Debug, PartialEq)]
pub struct BlindedSignatureShare(pub Scalar<Secret, NonZero>);

#[derive(Clone, Debug, PartialEq)]
pub struct Signature(pub Scalar<Secret, NonZero>);

/// * `threshold`: how many signature shares are needed to produce a signature
/// * `keys`: how many keys to generate
pub fn dealer_keygen(threshold: usize, n_parties: usize) -> (FrostKey, Vec<Point>, Vec<Scalar>) {
    let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
        Deterministic::<Sha256>::default(),
    ));
    let mut rng = OsRng; // FIXME: pass rng

    let mut scalar_polys = vec![];
    for _ in 1..=n_parties {
        let scalar_poly = (1..=threshold)
            .map(|_| {
                Scalar::from_non_zero_u32(
                    NonZeroU32::new(rng.gen::<u32>()).expect("impossibly unlikely to be zero"),
                )
            })
            .collect();
        scalar_polys.push(ScalarPoly::new(scalar_poly));
    }
    let point_polys: Vec<PointPoly> = scalar_polys.iter().map(|sp| sp.to_point_poly()).collect();

    let key_gen = frost.new_keygen(point_polys).unwrap();

    let mut proofs_of_possession = vec![];
    let mut shares_vec = vec![];
    for sp in scalar_polys {
        let (shares, pop) = frost.create_shares(&key_gen, sp);
        proofs_of_possession.push(pop);
        shares_vec.push(shares);
    }

    // collect the recieved shares for each party
    let mut recieved_shares: Vec<Vec<_>> = vec![];
    for party_index in 0..n_parties {
        recieved_shares.push(vec![]);
        for share_index in 0..n_parties {
            recieved_shares[party_index as usize]
                .push(shares_vec[share_index as usize][party_index as usize].clone());
        }
    }

    // finish keygen for each party
    let (secret_shares, frost_keys): (Vec<Scalar>, Vec<FrostKey>) = (0..n_parties)
        .map(|i| {
            let (secret_share, frost_key) = frost
                .finish_keygen(
                    key_gen.clone(),
                    i as u32,
                    recieved_shares[i as usize].clone(),
                    proofs_of_possession.clone(),
                )
                .unwrap();

            (secret_share, frost_key)
        })
        .unzip();

    let pub_verification_shares: Vec<_> = frost_keys[0].clone().verification_shares;

    (
        frost_keys[0].clone(),
        pub_verification_shares,
        secret_shares,
    )
}

pub fn blind_message(msg: Scalar) -> (BlindingKey, BlindedMessage) {
    let mut rng = OsRng;
    let blinding_key = Scalar::random(&mut rng);
    let blinded_msg = s!(blinding_key * msg);

    (BlindingKey(blinding_key), BlindedMessage(blinded_msg))
}

pub fn sign_blinded_msg(msg: BlindedMessage, secret_share: Scalar) -> BlindedSignatureShare {
    let sig = s!(secret_share * { msg.0 });
    BlindedSignatureShare(sig.mark::<NonZero>().expect("nonzero sig"))
}

pub fn unblind_signature(
    blinding_key: BlindingKey,
    blinded_sig: BlindedSignature,
) -> BlindedSignatureShare {
    let sig = s!({ blinded_sig.0 } * { blinding_key.0 });
    BlindedSignatureShare(sig.mark::<NonZero>().expect("nonzero sig"))
}

/// Combines a sufficent amount of valid blinded signature shares to a blinded signature. The
/// responsibility of verifying the supplied shares lies with the caller.
///
/// * `sig_shares`: an iterator yielding pairs of key indices and signature shares from said key
/// * `threshold`: number of shares needed to combine a signature
///
/// # Panics
/// If the amount of shares supplied is less than the necessary amount
pub fn combine_valid_shares<I>(
    frost_key: &FrostKey,
    sign_session: &SignSession,
    sig_shares: Vec<Scalar<Public, Zero>>,
    threshold: usize,
) -> BlindedSignature
where
    I: IntoIterator<Item = (usize, BlindedSignatureShare)>,
    I::IntoIter: Clone + ExactSizeIterator,
{
    let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
        Deterministic::<Sha256>::default(),
    ));
    let signature = frost.combine_signature_shares(frost_key, sign_session, sig_shares);
    // TODO probably wrong
    BlindedSignature(
        signature
            .s
            .mark::<NonZero>()
            .expect("nonzero sig")
            .mark::<Secret>(),
    )
}

#[cfg(test)]
mod tests {
    use crate::{blind_message, dealer_keygen, sign_blinded_msg};
    use schnorr_fun::{
        frost::{self, Frost},
        fun::marker::Public,
        nonce::Deterministic,
        Message, Schnorr,
    };
    use secp256kfun::{g, hash::HashAdd, s, Point, Scalar};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;

    #[test]
    fn test_keygen() {
        let (pk, pks, _sks) = dealer_keygen(5, 15);
        assert_eq!(pks.len(), 15);
    }

    #[test]
    fn test_frost_roundtrip() {
        // use SHA256 with deterministic nonce generation
        let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
            Deterministic::<Sha256>::default(),
        ));

        let message = Message::<Public>::plain("test", b"test");
        let msg = Scalar::from_hash(frost.schnorr.challenge_hash().add(message));

        let threshold = 5;
        let n_parties = 15;

        let (frost_key, _pks, secret_shares) = dealer_keygen(threshold, n_parties);

        let sid = [
            frost_key.joint_public_key.to_bytes().as_slice(),
            b"frost-very-unique-id".as_slice(),
            b"2".as_slice(),
        ]
        .concat();

        // generate nonces for this signing session
        let nonces: Vec<_> = (0..threshold)
            .map(|_| frost.gen_nonce(&secret_shares[0], &sid.clone()))
            .collect();

        let public_nonces = nonces
            .iter()
            .enumerate()
            .map(|(i, nonce)| (i as u32, nonce.public()))
            .collect();

        // BLIND THE MESSAGE!
        let (blinded_key, blinded_msg) = blind_message(msg);

        // start a sign session with these nonces for this message
        let session =
            frost.start_sign_session(&frost_key, public_nonces, Message::plain("test", b"test"));

        let sigs: Vec<_> = (0..threshold)
            .map(|i| {
                frost.sign(
                    &frost_key,
                    &session,
                    i as u32,
                    &secret_shares[i],
                    nonces[i].clone(),
                )
            })
            .collect();

        for (i, sig) in sigs.iter().enumerate() {
            assert!(frost.verify_signature_share(&frost_key, &session, i as u32, *sig));
        }

        let combined_sig = frost.combine_signature_shares(&frost_key, &session, sigs);
        assert!(frost.schnorr.verify(
            &frost_key.joint_public_key,
            Message::<Public>::plain("test", b"test"),
            &combined_sig
        ));
    }

    // #[test]
    // #[should_panic(expected = "Not enough signature shares")]
    // fn test_insufficient_shares() {
    //     let msg = Message::from_bytes(b"Hello World!");
    //     let threshold = 5;

    //     let (_, bmsg) = blind_message(msg);

    //     let (_, _pks, sks) = dealer_keygen(threshold, 4);

    //     let sigs = sks
    //         .iter()
    //         .enumerate()
    //         .map(|(idx, sk)| (idx, sign_blinded_msg(bmsg, *sk)));

    //     // Combining an insufficient number of signature shares should panic
    //     combine_valid_shares(sigs, threshold);
    // }
}
