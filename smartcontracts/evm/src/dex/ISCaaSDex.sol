// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";

/// @title The DEX side of `TradeOrder` (CTR-DEX-16, -17, -11, -03, -24): one taker against many makers per settlement,
///        every leg pulled into the DEX through its token's `mtxTrade`, every party, fee share and refund paid in the
///        same call, and the DEX's balance of every token unchanged at the end.
interface ISCaaSDex {
    /// @notice Written once by `initialize` (CTR-DEX-24). `relayerSharePpm` of every fee goes to the submitter, the
    ///         rest to `treasury`. `listedOnly` belongs to the exchange path (P2c).
    struct DexConfig {
        address admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
    }

    /// @notice One order in one settlement; `fill` = its `sellFill` in this call (Path B: the matched part).
    struct Leg {
        address sellToken;
        ITradeToken.TradeOrder o;
        bytes sig;
        uint256 fill;
    }

    /// @notice `ref` is the submitter's, echoed in events only; taker/makers is a call-time arrangement.
    struct Settlement {
        bytes32 ref;
        Leg taker;
        Leg[] makers;
    }

    event MarketSet(address indexed base, address indexed quote, bool listed);
    event FeeSplitSet(uint32 relayerSharePpm, address treasury);
    event LegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
    event MatchFailed(bytes32 indexed ref, bytes reason);

    error NotFactory();
    error AlreadyInitialized();
    error NotAdmin(address caller);
    error FeeSplitInvalid(uint32 relayerSharePpm, address treasury);
    error NotSelf();
    error NothingSettled();
    error NoMakers();
    error WrongRelayer(address submitter);
    error DexMismatch(address dex);
    error TokenMismatch();
    error SelfTrade(address from);
    error DuplicateOrder(bytes32 orderHash);
    error MarketNotListed(address tokenA, address tokenB);
    /// @notice An outside (non-SCaaS) token leg: `DexOrder` + `DexPuller` come with P2b-2.
    error OutsideLegNotBuilt(address token);
    error FillMismatch(uint256 expected, uint256 got);
    /// @notice Path B checks the DEX makes on the matched part (the token checks Path A itself).
    error BelowMinFill(bytes32 orderHash);
    error PriceLimit(bytes32 orderHash);
    error Overfill(bytes32 orderHash);
    error ConservationBroken(address token);

    function initialize(address creator, uint64 version, DexConfig calldata cfg) external;
    function setMarket(address base, address quote, bool listed) external;
    function setFeeSplit(uint32 relayerSharePpm, address treasury) external;
    function mtxSettle(Settlement[] calldata s) external returns (bool[] memory ok);

    function admin() external view returns (address);
    function relayerSharePpm() external view returns (uint32);
    function treasury() external view returns (address);
    function listedOnly() external view returns (bool);
    function marketListed(address a, address b) external view returns (bool);
    /// @notice 0 unknown, 1 SCaaS (made by the factory from a registered, non-deprecated version), 2 outside.
    function tokenKind(address token) external view returns (uint8);
    function factory() external view returns (address);
    function chainUid() external view returns (bytes32);
}
