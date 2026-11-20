package uniffi.scaas_sdk;


public enum FfiConverterTypeGasVerify implements FfiConverterRustBuffer<GasVerify> {
  INSTANCE;

  @Override
  public GasVerify read(java.nio.ByteBuffer buf) {
    return new GasVerify(
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterOptionalTypeGasPerItem.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasVerify value) {
      return (
            FfiConverterShort.INSTANCE.allocationSize(value.signer()) +
            FfiConverterLong.INSTANCE.allocationSize(value.gas()) +
            FfiConverterLong.INSTANCE.allocationSize(value.sigBytes()) +
            FfiConverterLong.INSTANCE.allocationSize(value.margin()) +
            FfiConverterOptionalTypeGasPerItem.INSTANCE.allocationSize(value.perItem())
      );
  }

  @Override
  public void write(GasVerify value, java.nio.ByteBuffer buf) {
      FfiConverterShort.INSTANCE.write(value.signer(), buf);
      FfiConverterLong.INSTANCE.write(value.gas(), buf);
      FfiConverterLong.INSTANCE.write(value.sigBytes(), buf);
      FfiConverterLong.INSTANCE.write(value.margin(), buf);
      FfiConverterOptionalTypeGasPerItem.INSTANCE.write(value.perItem(), buf);
  }
}



