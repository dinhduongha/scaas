package uniffi.scaas_sdk;


public enum FfiConverterTypeNativeAddress implements FfiConverterRustBuffer<NativeAddress> {
  INSTANCE;

  @Override
  public NativeAddress read(java.nio.ByteBuffer buf) {
    return new NativeAddress(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalByte.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(NativeAddress value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.network()) +
            FfiConverterString.INSTANCE.allocationSize(value.publicKey()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.address()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.ss58()) +
            FfiConverterOptionalByte.INSTANCE.allocationSize(value.witnessVersion()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.witnessProgram())
      );
  }

  @Override
  public void write(NativeAddress value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.network(), buf);
      FfiConverterString.INSTANCE.write(value.publicKey(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.address(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.ss58(), buf);
      FfiConverterOptionalByte.INSTANCE.write(value.witnessVersion(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.witnessProgram(), buf);
  }
}



