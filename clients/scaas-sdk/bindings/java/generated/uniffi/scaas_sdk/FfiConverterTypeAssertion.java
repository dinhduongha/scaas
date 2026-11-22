package uniffi.scaas_sdk;


public enum FfiConverterTypeAssertion implements FfiConverterRustBuffer<Assertion> {
  INSTANCE;

  @Override
  public Assertion read(java.nio.ByteBuffer buf) {
    return new Assertion(
      FfiConverterByteArray.INSTANCE.read(buf),
      FfiConverterByteArray.INSTANCE.read(buf),
      FfiConverterByteArray.INSTANCE.read(buf),
      FfiConverterByteArray.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Assertion value) {
      return (
            FfiConverterByteArray.INSTANCE.allocationSize(value.credentialId()) +
            FfiConverterByteArray.INSTANCE.allocationSize(value.authenticatorData()) +
            FfiConverterByteArray.INSTANCE.allocationSize(value.clientDataJson()) +
            FfiConverterByteArray.INSTANCE.allocationSize(value.signature()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.prf())
      );
  }

  @Override
  public void write(Assertion value, java.nio.ByteBuffer buf) {
      FfiConverterByteArray.INSTANCE.write(value.credentialId(), buf);
      FfiConverterByteArray.INSTANCE.write(value.authenticatorData(), buf);
      FfiConverterByteArray.INSTANCE.write(value.clientDataJson(), buf);
      FfiConverterByteArray.INSTANCE.write(value.signature(), buf);
      FfiConverterBoolean.INSTANCE.write(value.prf(), buf);
  }
}



