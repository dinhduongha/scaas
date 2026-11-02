// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// legacy/typed-signing: NOT COMPILED. What typed-signing C6 replaced, as it stood at the C4 head, from
// src/trade/TradeLib.sol, src/metatx/{ERC20MetaTx,MetaTokenBase,UAMetaTxBase,WrappedToken,WrappedLib,MtxRelayFee}.sol and
// src/dex/{ISCaaSDex,SCaaSDex}.sol: the digests over a digest, the wrap by `TradeOrder`, the router's `MetaTransfer` and the
// DEX's packed legs (TS-D19, Appendix X rows 9 and 20). Reference only.

// CancelOrder over the order hash, in the token's and the DEX's domain
bytes32 constant CANCEL_ORDER_TYPEHASH = keccak256("CancelOrder(bytes32 orderHash)");
// ReceiverFee over the payment digest
bytes32 constant RECEIVER_FEE_TYPEHASH =
    keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)");

abstract contract TradePreNested {
    function cancelOrderDigest(bytes32 orderHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(CANCEL_ORDER_TYPEHASH, orderHash)));
    }

    function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
        public view returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(RECEIVER_FEE_TYPEHASH, paymentDigest, fee, feeRecipient, validUntil)));
    }

    /// @notice The `metatx-cancel` digest (accounts.md §1.5): `CANCEL_TAG` is the purpose tag itself.
    function uaCancelDigest(bytes32 ua, uint256 batch, uint256 validUntil) public view virtual returns (bytes32) {
        return keccak256(abi.encode(
            UAKinds.PURPOSE_METATX_CANCEL, block.chainid, CHAIN_UID, address(this), ua, batch, validUntil
        ));
    }

    /// @notice Signature wrap of a SCaaS underlying (CTR-TOK-20): the order a `TradeOrder` with `dex == receiveToken`.
    function mtxWrap(address u, TradeOrder calldata o, bytes calldata sig)
        external nonReentrant returns (uint256 minted)
    {
        uint256 received;
        uint256 fee;
        (received, minted, fee) = WrappedLib.wrapBySig(u, o, sig, msg.sender);
        address to = o.destination == address(0) ? o.from : o.destination;
        _mint(to, minted - fee);
        if (fee != 0) _mint(msg.sender, fee);
        emit Wrapped(to, u, received, minted - fee);
    }

    function uaWrap(address u, UATradeOrder calldata o, bytes calldata auth)
        external nonReentrant returns (uint256 minted)
    {
        uint256 received;
        uint256 fee;
        (received, minted, fee) = WrappedLib.wrapBySigUA(u, o, auth, msg.sender);
        bytes32 to = o.destination == 0 ? o.from : o.destination;
        if (UAKinds.inNativeSpace(to)) _mint(address(uint160(uint256(to))), minted - fee);
        else _uaMint(to, minted - fee);
        if (fee != 0) _mint(msg.sender, fee);
        emit UAWrapped(to, u, received, minted - fee);
    }
}

/// `MtxRelayFee` on the token's typed transfer paths, the shape checked by the router.
abstract contract RouterPreRelayFee {
    function relay(address target, bytes calldata callData, address token, MetaTxLib.MetaTransfer calldata t,
                   bytes calldata sig) external nonReentrant
    {
        bytes32 ref = relayRef(target, callData);
        bytes32 to = MetaTxLib.pad(t.to);
        _shape(ref, target, t.entryRef, to, t.batch, t.nonce, t.mode, t.relayer, t.fee);
        MtxRelayExecutor(EXECUTOR).exec(target, callData);
        IERC20MetaTx(token).mtxExecuteTransfer(t, sig);
        emit RelayFeePaid(ref, target, token, MetaTxLib.pad(t.from), _payee(token, to, t.value), t.value);
    }

    function uaRelay(address target, bytes calldata callData, address token, MetaTxLib.UAMetaTransfer calldata t,
                     bytes calldata auth) external nonReentrant
    {
        bytes32 ref = relayRef(target, callData);
        _shape(ref, target, t.entryRef, t.to, t.batch, t.nonce, t.mode, t.relayer, t.fee);
        MtxRelayExecutor(EXECUTOR).exec(target, callData);
        IUALedger(token).uaExecuteTransfer(t, auth);
        emit RelayFeePaid(ref, target, token, t.from, _payee(token, t.to, t.value), t.value);
    }

    function _shape(bytes32 ref, address target, bytes32 entryRef, bytes32 to, uint256 batch, uint256 nonce, uint32 mode,
                    address relayer, uint256 fee) private view
    {
        if (entryRef != ref || batch != uint256(keccak256(abi.encodePacked("scaas.pay.lane", ref))) || nonce != 0
            || mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || relayer != address(this)
            || mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE || fee != 0
            || to == MetaTxLib.pad(EXECUTOR)) revert RelayFeeShape();
        if (!SigCheck.isContract(target)) revert RelayTargetNoCode(target);
    }
}

/// The DEX's legs: `order` = `abi.encode(TradeOrder)` (shape 0) or `abi.encode(UATradeOrder)` (shape 1), `sig` either's.
abstract contract DexPreLeg {
    struct Leg {
        address sellToken;
        uint8 shape;
        bytes order;
        bytes sig;
        uint256 fill;
    }

    struct ExchangeLeg {
        address sellToken;
        uint8 shape;
        bytes order;
        bytes sig;
        uint256 sellFill;
        uint256 receiveFill;
    }

    function _decode(address sellToken, uint8 shape, bytes calldata order) private view returns (Calc memory c) {
        if (shape > 1) revert LegShapeUnknown(shape);
        c.outside = _s().kind[sellToken] != KIND_SCAAS;
        if (shape == 0) {
            c.o = TradeLib.core(abi.decode(order, (ITradeToken.TradeOrder)));
        } else {
            if (!_ledgerOn(sellToken)) revert UALegNotLedger(sellToken);
            c.ua = true;
            c.o = abi.decode(order, (ITradeToken.UATradeOrder));
        }
    }
}
