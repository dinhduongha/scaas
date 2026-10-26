using Nethermind.Core;

namespace Nethermind.Pqz;

/// <summary>32-bit form (spec 2026-10-20 §12 item 9, plan 5h Task 8d; were P6f D3's <c>0x5caa5000…0f01</c> / <c>…0012</c>
/// / <c>…0013</c>): above 0xffff (outside EIP-1352), outside RIP-7587 and the L2 system ranges; <c>5caa</c> ≈ SCaaS, low
/// bytes = the old <c>0x…0F01</c> and EIP-8355's own 0x12 / 0x13. Same addresses on every chain that activates PQZ.</summary>
public static class PqzAddresses
{
    public static readonly Address Pqz = new("0x000000000000000000000000000000005caa0f01");
    public static readonly Address MlDsa44 = new("0x000000000000000000000000000000005caa0012");
    public static readonly Address MlDsa65 = new("0x000000000000000000000000000000005caa0013");
}
