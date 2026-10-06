//! `MetaOp` v1 cho CosmWasm (R30, R66): payload JSON chủ thể ký, miền nằm trong payload, kiểm chữ ký
//! ADR-036 (secp256k1) hoặc WebAuthn passkey (secp256r1). Contract nhận NGUYÊN bytes đã ký và parse chặt,
//! nên không có bước chính tắc hoá thứ hai có thể lệch với thứ ví đã ký.
use cosmwasm_std::{from_json, Addr, Api, Binary, CanonicalAddr, Env, HexBinary, StdError, StdResult, Uint128};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DOMAIN: &str = "scaas.metaop.v1";
pub const PASSKEY_TAG: &[u8] = b"scaas.passkey.v1";

/// Trường theo thứ tự chữ cái ⇒ `to_json_vec` cho ra đúng dạng chính tắc (khoá sắp xếp, không khoảng trắng).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetaOp {
    pub amount: Uint128,
    pub contract: String,
    pub domain: String,
    pub extra: String,
    pub from: String,
    pub lane: HexBinary,
    pub network: String,
    pub nonce: u64,
    pub op: String,
    pub pay_ref: HexBinary,
    pub relayer: String,
    pub to: String,
    pub valid_until: u64,
}

/// Chữ ký của chủ thể. `scheme`: `adr036` (secp256k1, Keplr/Leap/ví seed) | `passkey` (WebAuthn P-256).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub scheme: String,
    pub pubkey: Binary,
    pub signature: Binary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_data: Option<Binary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_data_json: Option<String>,
}

/// Hook CW20 `Send` → `{"receive": {...}}` ở contract nhận.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cw20ReceiveMsg {
    pub sender: String,
    pub amount: Uint128,
    pub msg: Binary,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverExecuteMsg {
    Receive(Cw20ReceiveMsg),
}

pub struct Verified {
    pub op: MetaOp,
    pub digest: [u8; 32],
    pub from: Addr,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn err(msg: impl std::fmt::Display) -> StdError {
    StdError::msg(msg)
}

/// Sign doc ADR-036 dựng bằng khuôn byte cố định (amino JSON khoá đã sắp, `chain_id` rỗng — review S7/S24).
pub fn adr036_doc(signer: &str, data: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"account_number":"0","chain_id":"","fee":{{"amount":[],"gas":"0"}},"memo":"","msgs":[{{"type":"sign/MsgSignData","value":{{"data":"{}","signer":"{}"}}}}],"sequence":"0"}}"#,
        Binary::from(data).to_base64(),
        signer
    )
    .into_bytes()
}

/// Địa chỉ tài khoản secp256k1 (Cosmos SDK): ripemd160(sha256(pk33)).
pub fn secp256k1_account(pk: &[u8]) -> Vec<u8> {
    Ripemd160::digest(sha256(pk)).to_vec()
}

/// Địa chỉ dẫn xuất của passkey (R9-1): sha256("scaas.passkey.v1" ‖ pk)[..20].
pub fn passkey_account(pk: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(PASSKEY_TAG);
    h.update(pk);
    h.finalize()[..20].to_vec()
}

pub fn base64url(data: &[u8]) -> String {
    Binary::from(data).to_base64().replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
}

/// Kiểm payload + chữ ký + miền + hạn. KHÔNG tiêu nonce (contract gọi tự giữ lane/nonce của nó).
pub fn verify(api: &dyn Api, env: &Env, payload: &[u8], auth: &Auth) -> StdResult<Verified> {
    let op: MetaOp = from_json(payload)?;
    if op.domain != DOMAIN {
        return Err(err("metaop: wrong domain"));
    }
    if op.network != env.block.chain_id {
        return Err(err("metaop: signed for another network"));
    }
    if op.contract != env.contract.address.as_str() {
        return Err(err("metaop: signed for another contract"));
    }
    if op.lane.len() != 32 || op.pay_ref.len() != 32 {
        return Err(err("metaop: lane and pay_ref are 32 bytes"));
    }
    if env.block.time.seconds() > op.valid_until {
        return Err(err("metaop: expired"));
    }
    let from = api.addr_validate(&op.from)?;
    let digest = sha256(payload);
    let pk = auth.pubkey.as_slice();
    let sig = auth.signature.as_slice();
    let (owner, ok) = match auth.scheme.as_str() {
        "adr036" => {
            if pk.len() != 33 {
                return Err(err("adr036: compressed secp256k1 public key expected"));
            }
            let hash = sha256(&adr036_doc(from.as_str(), payload));
            (secp256k1_account(pk), api.secp256k1_verify(&hash, sig, pk).map_err(err)?)
        }
        "passkey" => {
            let ad = auth.authenticator_data.as_ref().ok_or_else(|| err("passkey: authenticator_data missing"))?;
            let cdj = auth.client_data_json.as_ref().ok_or_else(|| err("passkey: client_data_json missing"))?;
            // Một khoá = một địa chỉ: chỉ dạng SEC1 không nén 65 byte (khoá COSE x‖y của WebAuthn).
            if pk.len() != 65 {
                return Err(err("passkey: uncompressed P-256 public key expected"));
            }
            if ad.len() < 37 || ad[32] & 0x01 == 0 {
                return Err(err("passkey: user presence flag not set"));
            }
            if !cdj.contains(r#""type":"webauthn.get""#)
                || !cdj.contains(&format!(r#""challenge":"{}""#, base64url(&digest)))
            {
                return Err(err("passkey: client data does not carry this operation"));
            }
            let mut msg = ad.to_vec();
            msg.extend_from_slice(&sha256(cdj.as_bytes()));
            (passkey_account(pk), api.secp256r1_verify(&sha256(&msg), sig, pk).map_err(err)?)
        }
        _ => return Err(err("unknown signature scheme")),
    };
    if api.addr_humanize(&CanonicalAddr::from(owner))? != from {
        return Err(err("public key does not own `from`"));
    }
    if !ok {
        return Err(err("bad signature"));
    }
    Ok(Verified { op, digest, from })
}
