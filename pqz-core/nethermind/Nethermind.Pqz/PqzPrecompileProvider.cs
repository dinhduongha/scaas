using System.Collections.Frozen;
using System.Collections.Generic;
using Nethermind.Blockchain;
using Nethermind.Core;
using Nethermind.Evm;
using Nethermind.Evm.CodeAnalysis;

namespace Nethermind.Pqz;

/// <summary>P6f D1: the Ethereum table plus PQZ, ML-DSA-44, ML-DSA-65 (the Taiko pattern). Whether a call reaches them
/// is decided by the release spec's precompile set (<see cref="PqzReleaseSpec"/>).</summary>
public class PqzPrecompileProvider : IPrecompileProvider
{
    private static readonly FrozenDictionary<AddressAsKey, CodeInfo> Table = new Dictionary<AddressAsKey, CodeInfo>(
        new EthereumPrecompileProvider().GetPrecompiles())
    {
        [PqzAddresses.Pqz] = new(PqzPrecompile.Instance),
        [PqzAddresses.MlDsa44] = new(MlDsa44Precompile.Instance),
        [PqzAddresses.MlDsa65] = new(MlDsa65Precompile.Instance),
    }.ToFrozenDictionary();

    public FrozenDictionary<AddressAsKey, CodeInfo> GetPrecompiles() => Table;
}
