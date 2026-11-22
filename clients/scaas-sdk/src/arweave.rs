// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Arweave as a store of ciphertext for app cores (CLI-SDK-21; feature `arweave`, without the EVM part; chains-arweave plan
//! T20): [`ArweaveFiles::upload_file`] posts an item `scaas-ua` built and verified (a kept item reloaded by the verifying parser,
//! the C9 shape required) through `scaas-rpc`'s bundler list; [`ArweaveFiles::keep_up`] reads settlement (CLI-RPC-13) and
//! re-posts the same bytes at 24 h, 72 h and 7 days, then `Unsettled`; [`ArweaveFiles::fetch_file`] reads the object within its
//! exact length, marked as feeding a decryption, accepted only with SHA-256 equal to `ctSha256`. Who pays (owner 2026-11-22,
//! decisions CLI-SDK-32; Arweave never depends on the node): the 2^16-B bucket on the free tier, best effort; a larger one, or a
//! free-tier refusal, by the configured [`Payer`]: the user's own credits (self-pay: the uploader's own item, a 402 is
//! `PaymentRequired`, [`SELF_PAY_NOTICE`] shown), or the operator's node payer (NODE-SPN-05: `x-paid-by` to that bundler only,
//! no payer `PayerUnavailable`); none configured: `PayerUnavailable`. The seal and the open are the app core's
//! (`AppCore::seal_for_arweave`, `AppCore::open_file`, feature `app-core`). No key is held here: a re-post cannot sign.
//! UNAUDITED.
use crate::error::SdkError;
use scaas_rpc::arweave::{owner_address, Bundlers, Gateways, Upload};
use scaas_rpc::endpoint::ListConfig;
use scaas_rpc::node::NodeClient;
use scaas_rpc::{FailureKind, Fanout, Purpose, RpcError};
use scaas_ua::arweave::{b64url, parse_ar_url, DataItem};
use scaas_ua::file::{check_object, object_len, BUCKET_MIN, CAP, TAG};

/// The re-post schedule after the send (C20): 24 h, 72 h, 7 days.
pub const REPOST_AFTER: [u64; 3] = [24 * 3600, 72 * 3600, 7 * 24 * 3600];
/// Shown before the first upload (§7.6, F17).
pub const PERMANENT_NOTICE: &str =
    "An Arweave object is public and permanent: deleting the message hides the message, never \
the object, and anyone who ever held the message can still open the file.";
/// Shown with a self-paid upload (owner 2026-11-22): the paying wallet links the user's upload keys at the bundler.
pub const SELF_PAY_NOTICE: &str =
    "Paying for uploads from your own wallet links every file you pay for to that wallet at the \
bundler: the per-file upload keys no longer keep your uploads apart there.";

fn net() -> String {
    "arweave.N.1".into()
}
fn depth() -> u64 {
    scaas_rpc::arweave::DEPTH
}

/// Who pays above the free tier.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum Payer {
    /// none: an object above the free tier is `PayerUnavailable`
    #[default]
    None,
    /// the user's own Turbo credits (or a per-upload payment): `paid_by` the user's credit address if credits are shared to
    /// the upload address, else none; a 402 is `PaymentRequired`
    SelfPay { paid_by: Option<String> },
    /// the operator's node payer (NODE-SPN-05), behind the app's gateway credential (`api_key_env` / `api_key_file`)
    Operator { node: ListConfig },
}

/// The release's Arweave data (CLI-RPC-02 lists), and the operator's or holder's `named` entries in them.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArweaveConfig {
    pub gateways: ListConfig,
    /// one operator per gateway, in order
    pub operators: Vec<String>,
    #[serde(default = "net")]
    pub network: String,
    pub bundlers: ListConfig,
    /// the bundler profile's largest single request, an object's bytes (set by the Turbo probe, T18)
    pub max_object: u64,
    #[serde(default = "depth")]
    pub depth: u64,
    #[serde(default)]
    pub payer: Payer,
}

/// How an accepted upload was paid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Paid {
    FreeTier,
    SelfPay,
    Operator { paid_by: String },
}

/// An upload a bundler accepted (never final: kept until settled).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadOutcome {
    pub id: String,
    pub url: String,
    pub accepted_by: Vec<usize>,
    pub paid: Paid,
    /// [`SELF_PAY_NOTICE`] with a self-paid upload
    pub notice: Option<&'static str>,
}

/// The signed bytes the app core keeps until settlement, with the send's time and the re-posts made.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeptUpload {
    pub item: Vec<u8>,
    pub sent_at: u64,
    pub reposts: u8,
}

/// Where a kept upload stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadState {
    /// settled (CLI-RPC-13): the app core may drop the bytes
    Settled,
    /// not settled, no re-post due
    Pending,
    /// re-posted now (the same bytes)
    Reposted,
    /// the last re-post made and still not settled (`UploadUnsettled`): shown; the bytes kept until settlement or deletion
    Unsettled,
}

enum PayerPath {
    None,
    SelfPay(Option<String>),
    Operator(NodeClient),
}

/// The Arweave calls of one release's lists.
pub struct ArweaveFiles {
    gateways: Gateways,
    bundlers: Bundlers,
    payer: PayerPath,
    depth: u64,
    max_object: u64,
}

fn rpc(e: RpcError) -> SdkError {
    SdkError::Rpc(e)
}

impl ArweaveFiles {
    /// The lists (`env` reads a credential's variable). `max_object` below the smallest object, or not one operator per
    /// gateway: `Argument`.
    pub fn new(
        cfg: &ArweaveConfig,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, SdkError> {
        if cfg.max_object < BUCKET_MIN + TAG {
            return Err(SdkError::Argument);
        }
        let gateways = Gateways::new(
            cfg.gateways.build(&env).map_err(rpc)?,
            cfg.operators.clone(),
            &cfg.network,
        )
        .map_err(rpc)?;
        let bundlers =
            Bundlers::new(cfg.bundlers.build(&env).map_err(rpc)?, cfg.max_object).map_err(rpc)?;
        let payer = match &cfg.payer {
            Payer::None => PayerPath::None,
            Payer::SelfPay { paid_by } => PayerPath::SelfPay(paid_by.clone()),
            Payer::Operator { node } => {
                PayerPath::Operator(NodeClient::new(node.build(&env).map_err(rpc)?).map_err(rpc)?)
            }
        };
        Ok(Self {
            gateways,
            bundlers,
            payer,
            depth: cfg.depth,
            max_object: cfg.max_object,
        })
    }

    /// The item of `bytes` by the verifying parser, C9 only (`ArweaveItem`), its object one of a bucket this release posts.
    fn item(&self, bytes: Vec<u8>) -> Result<(DataItem, u64), SdkError> {
        let it = DataItem::parse_c9(bytes).map_err(|_| SdkError::ArweaveItem)?;
        let n = it.data().len() as u64;
        let b = n
            .checked_sub(TAG)
            .filter(|b| b.is_power_of_two() && *b >= BUCKET_MIN)
            .ok_or(SdkError::ArweaveItem)?;
        if n > self.max_object {
            return Err(SdkError::FileTooLarge);
        }
        Ok((it, b))
    }

    async fn send(&self, it: &DataItem, paid_by: Option<&str>) -> Result<Upload, SdkError> {
        self.bundlers
            .upload(it.bytes(), Fanout::First, paid_by.map(|p| (0, p)))
            .await
            .map_err(rpc)
    }

    fn outcome(it: &DataItem, up: &Upload, paid: Paid) -> Option<UploadOutcome> {
        let Upload::Sent { outcomes, .. } = up else {
            return None;
        };
        let accepted_by = outcomes
            .iter()
            .filter(|(_, o)| matches!(o, scaas_rpc::arweave::BundlerOutcome::Accepted { .. }))
            .map(|(i, _)| *i)
            .collect();
        let notice = (paid == Paid::SelfPay).then_some(SELF_PAY_NOTICE);
        Some(UploadOutcome {
            id: it.id_b64(),
            url: it.url(),
            accepted_by,
            paid,
            notice,
        })
    }

    async fn post(&self, it: &DataItem, bucket: u64) -> Result<UploadOutcome, SdkError> {
        if bucket == BUCKET_MIN {
            let up = self.send(it, None).await?;
            if let Some(o) = Self::outcome(it, &up, Paid::FreeTier) {
                return Ok(o);
            }
        }
        let (up, paid) = match &self.payer {
            PayerPath::None => return Err(SdkError::PayerUnavailable),
            PayerPath::SelfPay(p) => (self.send(it, p.as_deref()).await?, Paid::SelfPay),
            PayerPath::Operator(n) => {
                let a = n
                    .arweave_payer(&owner_address(it), it.sig_type() as u16, bucket)
                    .await
                    .map_err(rpc)?
                    .ok_or(SdkError::PayerUnavailable)?;
                (
                    self.send(it, Some(&a.paid_by)).await?,
                    Paid::Operator { paid_by: a.paid_by },
                )
            }
        };
        if let Some(o) = Self::outcome(it, &up, paid) {
            return Ok(o);
        }
        Err(if up.payment_required() {
            SdkError::PaymentRequired
        } else {
            SdkError::UploadRejected
        })
    }

    /// Posts `item` (only an item `scaas-ua` built: reloaded by the verifying parser, C9) on the user's send: the 2^16-B
    /// bucket on the free tier, else (or on its refusal) by the payer. The app core keeps the bytes ([`KeptUpload`]).
    pub async fn upload_file(&self, item: Vec<u8>) -> Result<UploadOutcome, SdkError> {
        let (it, b) = self.item(item)?;
        self.post(&it, b).await
    }

    /// One look at a kept upload at `now` (Unix seconds): settled (strict majority of two operators, the depth, the bytes read
    /// back) is `Settled`; else the same bytes re-posted when the next of 24 h, 72 h, 7 days after the send is due (a payment
    /// refusal asks the payer again for the same address); after the last, `Unsettled`. Never re-signed: no key is here.
    pub async fn keep_up(&self, kept: &mut KeptUpload, now: u64) -> Result<UploadState, SdkError> {
        let (it, b) = self.item(kept.item.clone())?;
        if self
            .gateways
            .settled_item(&it, self.depth)
            .await
            .map_err(rpc)?
        {
            return Ok(UploadState::Settled);
        }
        let Some(after) = REPOST_AFTER.get(kept.reposts as usize) else {
            return Ok(UploadState::Unsettled);
        };
        if now < kept.sent_at.saturating_add(*after) {
            return Ok(UploadState::Pending);
        }
        kept.reposts += 1;
        // a refused re-post is not an error of this look: the bytes stay kept, the next look reads settlement again
        let _ = self.post(&it, b).await;
        Ok(if kept.reposts as usize == REPOST_AFTER.len() {
            UploadState::Unsettled
        } else {
            UploadState::Reposted
        })
    }

    /// The object named by `url` (`ar://<id>`) of a file of `size` bytes whose SHA-256 is `ct_sha256`: a malformed `url`
    /// (`Argument`) or a `size` whose bucket is above this platform's cap (`FileTooLarge`) refused before any request; read
    /// within the exact length, marked as feeding a decryption; every gateway's bytes failing the hash: `FileHashMismatch`.
    /// Shown on the device only; nothing sent depends on it (ARCH-POS-13). A PqVault item naming the object is written only
    /// after this has passed once (C14).
    pub async fn fetch_file(
        &self,
        url: &str,
        size: u64,
        ct_sha256: [u8; 32],
    ) -> Result<Vec<u8>, SdkError> {
        let id = parse_ar_url(url).map_err(|_| SdkError::Argument)?;
        let len = object_len(size, CAP).ok_or(SdkError::FileTooLarge)?;
        let check = move |b: &[u8]| check_object(b, size, &ct_sha256, CAP).is_ok();
        match self
            .gateways
            .data(&b64url(&id), len, Purpose::FeedsDecryption, &check)
            .await
        {
            Ok(b) => Ok(b),
            Err(RpcError::EndpointAllFailed { last: Some(f), .. })
                if f.kind == FailureKind::AnswerRefused =>
            {
                Err(SdkError::FileHashMismatch)
            }
            Err(e) => Err(rpc(e)),
        }
    }
}
