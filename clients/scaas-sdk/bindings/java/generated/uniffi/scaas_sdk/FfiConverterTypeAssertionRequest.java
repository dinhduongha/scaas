package uniffi.scaas_sdk;


public enum FfiConverterTypeAssertionRequest implements FfiConverterRustBuffer<AssertionRequest> {
  INSTANCE;

  @Override
  public AssertionRequest read(java.nio.ByteBuffer buf) {
    return new AssertionRequest(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByteArray.INSTANCE.read(buf),
      FfiConverterSequenceByteArray.INSTANCE.read(buf),
      FfiConverterOptionalByteArray.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AssertionRequest value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.rpId()) +
            FfiConverterByteArray.INSTANCE.allocationSize(value.challenge()) +
            FfiConverterSequenceByteArray.INSTANCE.allocationSize(value.allow()) +
            FfiConverterOptionalByteArray.INSTANCE.allocationSize(value.prfSalt())
      );
  }

  @Override
  public void write(AssertionRequest value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.rpId(), buf);
      FfiConverterByteArray.INSTANCE.write(value.challenge(), buf);
      FfiConverterSequenceByteArray.INSTANCE.write(value.allow(), buf);
      FfiConverterOptionalByteArray.INSTANCE.write(value.prfSalt(), buf);
  }
}



