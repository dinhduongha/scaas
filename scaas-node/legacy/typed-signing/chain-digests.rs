
    /// `mtxDigest(m)` / `mtxTransferDigest(t)`: exactly the digest the contract emits in `MetaTransactionExecuted` (R78).
    pub async fn mtx_digest(&self, token: Address, m: Mtx) -> std::result::Result<B256, SimError> {
        match m {
            Mtx::Call(m) => self.call_view(token, IToken::mtxDigestCall { m }).await,
            Mtx::Transfer(t) => self.call_view(token, IToken::mtxTransferDigestCall { t }).await,
        }
    }

    /// `uaDigest(m)` / `uaTransferDigest(t)`: the digest of `UAMetaTransactionExecuted`.
    pub async fn ua_digest(&self, token: Address, m: UaMtx) -> std::result::Result<B256, SimError> {
        match m {
            UaMtx::Call(m) => self.call_view(token, IUALedger::uaDigestCall { m }).await,
            UaMtx::Transfer(t) => self.call_view(token, IUALedger::uaTransferDigestCall { t }).await,
        }
    }

    /// The token's digest of a relayed `mtxExecute*` / `mtxPayMeta` or `uaExecute*` / `uaPayMeta` calldata; `None` for
    /// any other call.
    pub async fn digest_of(&self, token: Address, data: &[u8]) -> Option<std::result::Result<B256, SimError>> {
        if let Some((m, _)) = Mtx::from_calldata(data) {
            return Some(self.mtx_digest(token, m).await);
        }
        Some(self.ua_digest(token, UaMtx::from_calldata(data)?.0).await)
    }

