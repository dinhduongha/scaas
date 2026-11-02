
    /// Cancel one order with a `CancelOrder(orderHash)` signature (the sell token's domain, or the DEX's for an
    /// outside token): out of the book NOW, then closed on chain at the next sync.
    pub async fn cancel(&self, h: B256, signature: &str) -> std::result::Result<(), VenueError> {
        let sig = sig_bytes(signature)?;
        let mut book = self.book.lock().await;
        let r = book.get(h).cloned().ok_or_else(|| bad("order is not in the book"))?;
        let kind = self.kind(r.sell);
        let digest = match kind {
            KIND_SCAAS => view(&self.chain, r.sell, IToken::cancelOrderDigestCall { orderHash: h }).await,
            _ => view(&self.chain, self.dex, ISCaaSDex::cancelOrderDigestCall { orderHash: h }).await,
        }
        .map_err(down)?;
        if !self.valid_sig(self.verifier(r.sell), r.order.from, digest, &sig).await.map_err(down)? {
            return Err(bad("bad cancel signature"));
        }
        let market_id = book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default();
        let mut next = book.clone();
        next.remove(h);
        let mut commit = Commit::default();
        commit.order(market_id, &r, "cancelled");
        self.commit_or_reload(&mut book, next, commit).await?;
        if let Ok(mut q) = self.cancels.lock() {
            if q.allow(r.order.from, now()) {
                q.pending.push((market_id, r.sell, kind, r.order, sig));
            }
        }
        Ok(())
    }

    /// Cancel-all of a lane: `InvalidateNonces(from, batch, minNonce)` in the sell token's domain (its SCaaS orders)
    /// or the DEX's (every outside-token order). Only while the signer has an open order there (gas spam).
    pub async fn cancel_all(&self, sell: Address, from: Address, batch: U256, min: U256, signature: &str)
        -> std::result::Result<usize, VenueError>
    {
        let sig = sig_bytes(signature)?;
        let kind = self.kind(sell);
        let outside = kind == KIND_OUTSIDE;
        let in_scope = |s: Address| if outside { self.kind(s) == KIND_OUTSIDE } else { s == sell };
        let mut book = self.book.lock().await;
        let open: Vec<Resting> = book.open_of(from).into_iter().filter(|r| r.order.batch == batch && in_scope(r.sell)).cloned().collect();
        let Some(first) = open.first() else { return Err(bad("no open order of this signer on that lane")) };
        let market_id = book.market_of(first.sell, first.order.receiveToken).map(|m| m.id).unwrap_or_default();
        let (target, digest, call) = if outside {
            (self.dex, view(&self.chain, self.dex, ISCaaSDex::invalidateNoncesDigestCall { from, batch, newMin: min }).await,
             ISCaaSDex::mtxInvalidateNoncesCall { from, batch, newMin: min, sig: sig.clone() }.abi_encode())
        } else {
            (sell, view(&self.chain, sell, IToken::invalidateNoncesDigestCall { from, batch, newMin: min }).await,
             IToken::mtxInvalidateNoncesCall { from, batch, newMin: min, sig: sig.clone() }.abi_encode())
        };
        if !self.valid_sig(target, from, digest.map_err(down)?, &sig).await.map_err(down)? {
            return Err(bad("bad invalidate signature"));
        }
        // already at or past `min` on chain (MinNonceNotIncreasing): the orders are closed, no job needed
        let job_needed = match self.call(self.relayer(), target, call.clone()).await {
            Ok(_) => true,
            Err(SimError::Revert(r)) if r.starts_with("MinNonceNotIncreasing(") => false,
            Err(e) => return Err(bad(format!("mtxInvalidateNonces refused: {e}"))),
        };
        let mut next = book.clone();
        let gone = next.drop_below(from, batch, min, &in_scope);
        let mut commit = Commit::default();
        for r in &gone {
            commit.order(book.market_of(r.sell, r.order.receiveToken).map(|m| m.id).unwrap_or_default(), r, "cancelled");
        }
        let allowed = self.cancels.lock().map(|mut q| q.allow(from, now())).unwrap_or(false);
        if job_needed && allowed {
            let valid_until = (now() + CANCEL_JOB_SECS).to_string();
            commit.jobs.push(if outside {
                json!({"kind": "invalidate", "market_id": market_id, "target": format!("{:#x}", self.dex),
                       "calldata": hex_of(&call), "valid_until": valid_until, "tags": []})
            } else {
                json!({"kind": "metatx", "entry": "mtxInvalidateNonces", "market_id": market_id,
                       "token": format!("{sell:#x}"), "from": format!("{from:#x}"), "batch": batch.to_string(),
                       "newMin": min.to_string(), "signature": hex_of(&sig), "validUntil": valid_until})
            });
        }
        self.commit_or_reload(&mut book, next, commit).await?;
        Ok(gone.len())
