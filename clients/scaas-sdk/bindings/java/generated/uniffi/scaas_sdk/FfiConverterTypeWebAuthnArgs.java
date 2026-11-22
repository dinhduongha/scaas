package uniffi.scaas_sdk;


public enum FfiConverterTypeWebAuthnArgs implements FfiConverterRustBuffer<WebAuthnArgs> {
  INSTANCE;

  @Override
  public WebAuthnArgs read(java.nio.ByteBuffer buf) {
    return new WebAuthnArgs(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(WebAuthnArgs value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.x()) +
            FfiConverterString.INSTANCE.allocationSize(value.y()) +
            FfiConverterString.INSTANCE.allocationSize(value.rpIdHash())
      );
  }

  @Override
  public void write(WebAuthnArgs value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.x(), buf);
      FfiConverterString.INSTANCE.write(value.y(), buf);
      FfiConverterString.INSTANCE.write(value.rpIdHash(), buf);
  }
}



