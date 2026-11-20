package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherUnshield implements FfiConverterRustBuffer<ZetherUnshield> {
  INSTANCE;

  @Override
  public ZetherUnshield read(java.nio.ByteBuffer buf) {
    return new ZetherUnshield(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
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
  public long allocationSize(ZetherUnshield value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.recipient()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntilBlock()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.tableBits()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.boundBits())
      );
  }

  @Override
  public void write(ZetherUnshield value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.recipient(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntilBlock(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.tableBits(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.boundBits(), buf);
  }
}



