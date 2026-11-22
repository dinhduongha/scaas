package uniffi.scaas_sdk;


public enum FfiConverterTypeChainProfile implements FfiConverterRustBuffer<ChainProfile> {
  INSTANCE;

  @Override
  public ChainProfile read(java.nio.ByteBuffer buf) {
    return new ChainProfile(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeFamily.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterSequenceTypeEndpointConfig.INSTANCE.read(buf),
      FfiConverterTypePolicy.INSTANCE.read(buf),
      FfiConverterSequenceTypeEndpointConfig.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterTypeFinality.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterSequenceTypeListedToken.INSTANCE.read(buf),
      FfiConverterTypeGasRows.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterSequenceTypeEndpointConfig.INSTANCE.read(buf),
      FfiConverterTypePolicy.INSTANCE.read(buf),
      FfiConverterSequenceTypeListedDex.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf),
      FfiConverterOptionalTypeFamilyParams.INSTANCE.read(buf),
      FfiConverterOptionalTypeL1Fee.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ChainProfile value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.key()) +
            FfiConverterTypeFamily.INSTANCE.allocationSize(value.family()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.chainId()) +
            FfiConverterString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterSequenceTypeEndpointConfig.INSTANCE.allocationSize(value.rpc()) +
            FfiConverterTypePolicy.INSTANCE.allocationSize(value.rpcPolicy()) +
            FfiConverterSequenceTypeEndpointConfig.INSTANCE.allocationSize(value.gateways()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.registry()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.factory()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.router()) +
            FfiConverterTypeFinality.INSTANCE.allocationSize(value.finality()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.txGasCap()) +
            FfiConverterSequenceTypeListedToken.INSTANCE.allocationSize(value.tokens()) +
            FfiConverterTypeGasRows.INSTANCE.allocationSize(value.gas()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.gasOptIn()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.maxValidSecs()) +
            FfiConverterSequenceTypeEndpointConfig.INSTANCE.allocationSize(value.verifiers()) +
            FfiConverterTypePolicy.INSTANCE.allocationSize(value.verifierPolicy()) +
            FfiConverterSequenceTypeListedDex.INSTANCE.allocationSize(value.dexes()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.wrappers()) +
            FfiConverterOptionalTypeFamilyParams.INSTANCE.allocationSize(value.familyParams()) +
            FfiConverterOptionalTypeL1Fee.INSTANCE.allocationSize(value.l1Fee()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.disabledKinds()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.pinnedReads())
      );
  }

  @Override
  public void write(ChainProfile value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.key(), buf);
      FfiConverterTypeFamily.INSTANCE.write(value.family(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.chainId(), buf);
      FfiConverterString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterSequenceTypeEndpointConfig.INSTANCE.write(value.rpc(), buf);
      FfiConverterTypePolicy.INSTANCE.write(value.rpcPolicy(), buf);
      FfiConverterSequenceTypeEndpointConfig.INSTANCE.write(value.gateways(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.registry(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.factory(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.router(), buf);
      FfiConverterTypeFinality.INSTANCE.write(value.finality(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.txGasCap(), buf);
      FfiConverterSequenceTypeListedToken.INSTANCE.write(value.tokens(), buf);
      FfiConverterTypeGasRows.INSTANCE.write(value.gas(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.gasOptIn(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.maxValidSecs(), buf);
      FfiConverterSequenceTypeEndpointConfig.INSTANCE.write(value.verifiers(), buf);
      FfiConverterTypePolicy.INSTANCE.write(value.verifierPolicy(), buf);
      FfiConverterSequenceTypeListedDex.INSTANCE.write(value.dexes(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.wrappers(), buf);
      FfiConverterOptionalTypeFamilyParams.INSTANCE.write(value.familyParams(), buf);
      FfiConverterOptionalTypeL1Fee.INSTANCE.write(value.l1Fee(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.disabledKinds(), buf);
      FfiConverterBoolean.INSTANCE.write(value.pinnedReads(), buf);
  }
}



