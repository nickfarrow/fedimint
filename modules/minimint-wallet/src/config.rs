use crate::{Feerate, PegInDescriptor};

use bitcoin::Network;
use minimint_api::config::GenerateConfig;
use minimint_api::PeerId;
use miniscript::descriptor::Tr;
use miniscript::Descriptor;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::frost;

const FINALITY_DELAY: u32 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub peg_in_descriptor: PegInDescriptor,
    pub peer_verification_shares: BTreeMap<PeerId, frost::VerificationShare>,
    pub peg_in_key: frost::Scalar,
    pub frost_key: frost::XOnlyFrostKey,
    pub finality_delay: u32,
    pub default_fee: Feerate,
    pub btc_rpc_address: String,
    pub btc_rpc_user: String,
    pub btc_rpc_pass: String,
    pub fee_consensus: FeeConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletClientConfig {
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The bitcoin network the client will use
    pub network: Network,
    /// Confirmations required for a peg in to be accepted by federation
    pub finality_delay: u32,
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub peg_in_abs: minimint_api::Amount,
    pub peg_out_abs: minimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            peg_in_abs: minimint_api::Amount::ZERO,
            peg_out_abs: minimint_api::Amount::ZERO,
        }
    }
}

impl GenerateConfig for WalletConfig {
    type Params = ();
    type ClientConfig = WalletClientConfig;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        _params: &Self::Params,
        _rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let threshold = peers.len() - max_evil;

        let (secret_shares, frost_key) =
            frost::trusted_frost_gen(threshold as u32, peers.len() as u32);
        let verification_shares: BTreeMap<PeerId, frost::VerificationShare> = peers
            .iter()
            .cloned()
            .map(|id| id)
            .zip(frost_key.verification_shares())
            .collect();

        let peg_in_descriptor =
            Descriptor::Tr(Tr::new(frost_key.public_key().to_xonly().into(), None).unwrap());

        let wallet_cfgs: BTreeMap<PeerId, Self> = peers
            .iter()
            .cloned()
            .zip(secret_shares)
            .map(|(peer_id, secret_share)| {
                let wallet_cfg = WalletConfig {
                    network: Network::Regtest,
                    peg_in_key: secret_share,
                    peg_in_descriptor: peg_in_descriptor.clone(),
                    finality_delay: FINALITY_DELAY,
                    default_fee: Feerate { sats_per_kvb: 1000 },
                    btc_rpc_address: "127.0.0.1:18443".to_string(),
                    btc_rpc_user: "bitcoin".to_string(),
                    btc_rpc_pass: "bitcoin".to_string(),
                    fee_consensus: FeeConsensus::default(),
                    peer_verification_shares: verification_shares.clone(),
                    frost_key: frost_key.clone(),
                };
                (peer_id, wallet_cfg)
            })
            .collect();

        let client_cfg = WalletClientConfig {
            peg_in_descriptor,
            network: Network::Regtest,
            finality_delay: FINALITY_DELAY,
            fee_consensus: FeeConsensus::default(),
        };

        (wallet_cfgs, client_cfg)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        WalletClientConfig {
            peg_in_descriptor: self.peg_in_descriptor.clone(),
            network: self.network,
            fee_consensus: self.fee_consensus.clone(),
            finality_delay: self.finality_delay,
        }
    }
}
