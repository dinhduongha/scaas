package uniffi.scaas_sdk;


public enum FfiConverterTypeRegisterArgs implements FfiConverterRustBuffer<RegisterArgs> {
  INSTANCE;

  @Override
  public RegisterArgs read(java.nio.ByteBuffer buf) {
    return new RegisterArgs(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalShort.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalTypeWebAuthnArgs.INSTANCE.read(buf),
      FfiConverterTypeAttrsArgs.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(RegisterArgs value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.entry()) +
            FfiConverterOptionalShort.INSTANCE.allocationSize(value.kind()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.keyData()) +
            FfiConverterOptionalTypeWebAuthnArgs.INSTANCE.allocationSize(value.key()) +
            FfiConverterTypeAttrsArgs.INSTANCE.allocationSize(value.attrs()) +
            FfiConverterString.INSTANCE.allocationSize(value.pqzPop()) +
            FfiConverterString.INSTANCE.allocationSize(value.pop())
      );
  }

  @Override
  public void write(RegisterArgs value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.entry(), buf);
      FfiConverterOptionalShort.INSTANCE.write(value.kind(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.keyData(), buf);
      FfiConverterOptionalTypeWebAuthnArgs.INSTANCE.write(value.key(), buf);
      FfiConverterTypeAttrsArgs.INSTANCE.write(value.attrs(), buf);
      FfiConverterString.INSTANCE.write(value.pqzPop(), buf);
      FfiConverterString.INSTANCE.write(value.pop(), buf);
  }
}



