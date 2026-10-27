//! Spike (plan Task 1, spec §3.5 / R8): a two-passkey `relay_fee_<entry>` modelled as its largest wrapper's work (§3.8):
//! the entry's passkey auth + the payment's, keccak over `call`, one 8-key account record, one lane, two balances,
//! two NEP-297 logs. Returns the gas used by each `verify` (env::used_gas deltas).
use near_sdk::{borsh, env, near};
use scaas_near_common::webauthn::verify;

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct PasskeyCase {
    pub key: [u8; 64],
    pub challenge: [u8; 32],
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub sig: [u8; 64],
    pub rp_id_hash: [u8; 32],
    pub origins: Vec<String>,
}

fn auth(c: &PasskeyCase) -> Result<(), scaas_near_common::webauthn::AuthError> {
    verify(&c.key, &c.challenge, &c.authenticator_data, &c.client_data_json, &c.sig, &c.rp_id_hash, &c.origins)
}

#[near(contract_state)]
#[derive(Default)]
pub struct Spike {}

#[near]
impl Spike {
    /// Borsh args (a, b, call); JSON result [gas verify a, gas verify b].
    pub fn two_passkey(
        &mut self,
        #[serializer(borsh)] a: PasskeyCase,
        #[serializer(borsh)] b: PasskeyCase,
        #[serializer(borsh)] call: Vec<u8>,
    ) -> Vec<u64> {
        let g0 = env::used_gas();
        auth(&a).unwrap_or_else(|e| env::panic_str(&format!("passkey a: {e:?}")));
        let g1 = env::used_gas();
        auth(&b).unwrap_or_else(|e| env::panic_str(&format!("passkey b: {e:?}")));
        let g2 = env::used_gas();

        let r = env::keccak256_array(&call);
        // Account record: 8 keys (kind, x ‖ y, rpIdHash, origin).
        let keys: Vec<(u16, [u8; 64], [u8; 32], String)> = (0..8)
            .map(|i| { let c = if i % 2 == 0 { &a } else { &b }; (0x0103, c.key, c.rp_id_hash, c.origins[0].clone()) })
            .collect();
        env::storage_write(b"a:alice.test.near", &borsh::to_vec(&keys).unwrap());
        env::storage_write(&[b"l:".as_slice(), &r].concat(), &1u64.to_le_bytes());
        for who in [b"b:alice.test.near".as_slice(), b"b:relayer.test.near"] {
            let bal = env::storage_read(who).map_or(0u128, |v| u128::from_le_bytes(v.try_into().unwrap()));
            env::storage_write(who, &(bal + 1_000).to_le_bytes());
        }
        let ref_hex: String = r.iter().map(|x| format!("{x:02x}")).collect();
        env::log_str(&format!(
            r#"EVENT_JSON:{{"standard":"nep141","version":"1.0.0","event":"ft_transfer","data":[{{"old_owner_id":"alice.test.near","new_owner_id":"relayer.test.near","amount":"1000","memo":"{ref_hex}"}}]}}"#
        ));
        env::log_str(&format!(
            r#"EVENT_JSON:{{"standard":"scaas","version":"1.0.0","event":"relay_fee_paid","data":[{{"ref":"{ref_hex}","payer":"alice.test.near","relayer":"relayer.test.near","amount":"1000"}}]}}"#
        ));
        vec![(g1.as_gas() - g0.as_gas()), (g2.as_gas() - g1.as_gas())]
    }

    /// "ok" or the AuthError name; the vector test runs the on-chain code path.
    pub fn check(&self, #[serializer(borsh)] c: PasskeyCase) -> String {
        auth(&c).map_or_else(|e| format!("{e:?}"), |_| "ok".into())
    }
}
