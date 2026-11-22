package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherTransferMulti implements FfiConverterRustBuffer<ZetherTransferMulti> {
  INSTANCE;

  @Override
  public ZetherTransferMulti read(java.nio.ByteBuffer buf) {
    return new ZetherTransferMulti(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterSequenceTypeZetherLeg.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherTransferMulti value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterSequenceTypeZetherLeg.INSTANCE.allocationSize(value.recipients()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.decoys()) +
            FfiConverterString.INSTANCE.allocationSize(value.decoyFee()) +
            FfiConverterLong.INSTANCE.allocationSize(value.uaSignerGas()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntilBlock()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.tableBits()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.boundBits())
      );
  }

  @Override
  public void write(ZetherTransferMulti value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterSequenceTypeZetherLeg.INSTANCE.write(value.recipients(), buf);
      FfiConverterInteger.INSTANCE.write(value.decoys(), buf);
      FfiConverterString.INSTANCE.write(value.decoyFee(), buf);
      FfiConverterLong.INSTANCE.write(value.uaSignerGas(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntilBlock(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.tableBits(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.boundBits(), buf);
  }
}



