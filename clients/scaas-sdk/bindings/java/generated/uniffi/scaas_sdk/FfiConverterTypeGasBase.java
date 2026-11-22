package uniffi.scaas_sdk;


public enum FfiConverterTypeGasBase implements FfiConverterRustBuffer<GasBase> {
  INSTANCE;

  @Override
  public GasBase read(java.nio.ByteBuffer buf) {
    return new GasBase(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterOptionalTypeGasPerByte.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterOptionalTypeGasPerItem.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasBase value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.entry()) +
            FfiConverterString.INSTANCE.allocationSize(value.kind()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.fresh()) +
            FfiConverterLong.INSTANCE.allocationSize(value.gas()) +
            FfiConverterOptionalTypeGasPerByte.INSTANCE.allocationSize(value.perByte()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.save()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.feeExtra()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.uaExtra()) +
            FfiConverterOptionalTypeGasPerItem.INSTANCE.allocationSize(value.perItem()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.regular())
      );
  }

  @Override
  public void write(GasBase value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.entry(), buf);
      FfiConverterString.INSTANCE.write(value.kind(), buf);
      FfiConverterBoolean.INSTANCE.write(value.fresh(), buf);
      FfiConverterLong.INSTANCE.write(value.gas(), buf);
      FfiConverterOptionalTypeGasPerByte.INSTANCE.write(value.perByte(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.save(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.feeExtra(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.uaExtra(), buf);
      FfiConverterOptionalTypeGasPerItem.INSTANCE.write(value.perItem(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.regular(), buf);
  }
}



