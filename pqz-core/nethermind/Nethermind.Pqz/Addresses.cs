using Nethermind.Core;

namespace Nethermind.Pqz;

/// <summary>P6f D3: outside EIP-1352 (above 0xffff), RIP-7587 and the L2 system ranges; "5caa5" ≈ SCaaS, low bytes =
/// the old <c>0x…0F01</c> and EIP-8355's own 0x12 / 0x13. Same addresses on every chain that activates PQZ.</summary>
public static class PqzAddresses
{
    public static readonly Address Pqz = new("0x5caa500000000000000000000000000000000f01");
    public static readonly Address MlDsa44 = new("0x5caa500000000000000000000000000000000012");
    public static readonly Address MlDsa65 = new("0x5caa500000000000000000000000000000000013");
}
