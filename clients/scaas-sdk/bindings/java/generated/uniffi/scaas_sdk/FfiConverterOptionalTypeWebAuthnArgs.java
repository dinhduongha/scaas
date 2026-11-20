package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeWebAuthnArgs implements FfiConverterRustBuffer<WebAuthnArgs> {
  INSTANCE;

  @Override
  public WebAuthnArgs read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeWebAuthnArgs.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(WebAuthnArgs value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeWebAuthnArgs.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(WebAuthnArgs value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeWebAuthnArgs.INSTANCE.write(value, buf);
    }
  }
}



