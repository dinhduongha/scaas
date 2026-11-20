package uniffi.scaas_sdk;


public enum FfiConverterTypeNativeQuote implements FfiConverterRustBuffer<NativeQuote> {
  INSTANCE;

  @Override
  public NativeQuote read(java.nio.ByteBuffer buf) {
    return new NativeQuote(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeSubmitQuote.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(NativeQuote value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.key()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.from()) +
            FfiConverterString.INSTANCE.allocationSize(value.to()) +
            FfiConverterString.INSTANCE.allocationSize(value.value()) +
            FfiConverterString.INSTANCE.allocationSize(value.data()) +
            FfiConverterTypeSubmitQuote.INSTANCE.allocationSize(value.quote()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.delegated())
      );
  }

  @Override
  public void write(NativeQuote value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.key(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.from(), buf);
      FfiConverterString.INSTANCE.write(value.to(), buf);
      FfiConverterString.INSTANCE.write(value.value(), buf);
      FfiConverterString.INSTANCE.write(value.data(), buf);
      FfiConverterTypeSubmitQuote.INSTANCE.write(value.quote(), buf);
      FfiConverterBoolean.INSTANCE.write(value.delegated(), buf);
  }
}



