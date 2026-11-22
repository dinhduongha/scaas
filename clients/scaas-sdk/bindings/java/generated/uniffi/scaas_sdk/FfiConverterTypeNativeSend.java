package uniffi.scaas_sdk;


public enum FfiConverterTypeNativeSend implements FfiConverterRustBuffer<NativeSend> {
  INSTANCE;

  @Override
  public NativeSend read(java.nio.ByteBuffer buf) {
    return new NativeSend(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalByte.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(NativeSend value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.key()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.to()) +
            FfiConverterString.INSTANCE.allocationSize(value.value()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.data()) +
            FfiConverterOptionalByte.INSTANCE.allocationSize(value.txType())
      );
  }

  @Override
  public void write(NativeSend value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.key(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.to(), buf);
      FfiConverterString.INSTANCE.write(value.value(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.data(), buf);
      FfiConverterOptionalByte.INSTANCE.write(value.txType(), buf);
  }
}



