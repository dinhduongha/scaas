package uniffi.scaas_sdk;


public enum FfiConverterTypePasskeyCreated implements FfiConverterRustBuffer<PasskeyCreated> {
  INSTANCE;

  @Override
  public PasskeyCreated read(java.nio.ByteBuffer buf) {
    return new PasskeyCreated(
      FfiConverterByteArray.INSTANCE.read(buf),
      FfiConverterByteArray.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PasskeyCreated value) {
      return (
            FfiConverterByteArray.INSTANCE.allocationSize(value.credentialId()) +
            FfiConverterByteArray.INSTANCE.allocationSize(value.keyData())
      );
  }

  @Override
  public void write(PasskeyCreated value, java.nio.ByteBuffer buf) {
      FfiConverterByteArray.INSTANCE.write(value.credentialId(), buf);
      FfiConverterByteArray.INSTANCE.write(value.keyData(), buf);
  }
}



