// Lazy-loaded by the portal only when a Zether (confidential balance) key is needed (R33).
export {
  deriveConfKey, confPublic, zetherKind, zetherPop, zetherSign, zetherOwnerAuth, schnorrVerify, sealConfKey, openConfKey, USE_CONF,
  // balance cache (zether-limits §5)
  DEVICE_BOUND_BITS, checkBalance, sealBalanceCache, openBalanceCache, setCachedBalance, cacheAfterDebit,
  cacheAfterRollOver, readBalance,
} from './zether.js';
