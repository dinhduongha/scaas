package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherUnshieldUnwrap implements FfiConverterRustBuffer<ZetherUnshieldUnwrap> {
  INSTANCE;

  @Override
  public ZetherUnshieldUnwrap read(java.nio.ByteBuffer buf) {
    return new ZetherUnshieldUnwrap(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherUnshieldUnwrap value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.underlying()) +
            FfiConverterString.INSTANCE.allocationSize(value.recipient()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterString.INSTANCE.allocationSize(value.minOut()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntilBlock()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.tableBits()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.boundBits())
      );
  }

  @Override
  public void write(ZetherUnshieldUnwrap value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.underlying(), buf);
      FfiConverterString.INSTANCE.write(value.recipient(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterString.INSTANCE.write(value.minOut(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntilBlock(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.tableBits(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.boundBits(), buf);
  }
}



