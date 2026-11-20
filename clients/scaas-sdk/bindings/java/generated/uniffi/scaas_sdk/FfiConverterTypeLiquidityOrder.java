package uniffi.scaas_sdk;


public enum FfiConverterTypeLiquidityOrder implements FfiConverterRustBuffer<LiquidityOrder> {
  INSTANCE;

  @Override
  public LiquidityOrder read(java.nio.ByteBuffer buf) {
    return new LiquidityOrder(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterSequenceTypeLiquidityToken.INSTANCE.read(buf),
      FfiConverterSequenceTypeLiquidityToken.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(LiquidityOrder value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.dex()) +
            FfiConverterSequenceTypeLiquidityToken.INSTANCE.allocationSize(value.inputs()) +
            FfiConverterSequenceTypeLiquidityToken.INSTANCE.allocationSize(value.outputs()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.positionManager()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.positionReader()) +
            FfiConverterString.INSTANCE.allocationSize(value.positionIn()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.positionPool()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.tickLower()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.tickUpper()) +
            FfiConverterString.INSTANCE.allocationSize(value.minLiquidity()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.recipient()) +
            FfiConverterString.INSTANCE.allocationSize(value.fee()) +
            FfiConverterString.INSTANCE.allocationSize(value.relayer()) +
            FfiConverterByte.INSTANCE.allocationSize(value.flags()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.nonce()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntil()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.extraTokens()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.partial())
      );
  }

  @Override
  public void write(LiquidityOrder value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.dex(), buf);
      FfiConverterSequenceTypeLiquidityToken.INSTANCE.write(value.inputs(), buf);
      FfiConverterSequenceTypeLiquidityToken.INSTANCE.write(value.outputs(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.positionManager(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.positionReader(), buf);
      FfiConverterString.INSTANCE.write(value.positionIn(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.positionPool(), buf);
      FfiConverterInteger.INSTANCE.write(value.tickLower(), buf);
      FfiConverterInteger.INSTANCE.write(value.tickUpper(), buf);
      FfiConverterString.INSTANCE.write(value.minLiquidity(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.recipient(), buf);
      FfiConverterString.INSTANCE.write(value.fee(), buf);
      FfiConverterString.INSTANCE.write(value.relayer(), buf);
      FfiConverterByte.INSTANCE.write(value.flags(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.nonce(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntil(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.extraTokens(), buf);
      FfiConverterBoolean.INSTANCE.write(value.partial(), buf);
  }
}



