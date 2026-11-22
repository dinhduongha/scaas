package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeEndpointAuth implements FfiConverterRustBuffer<EndpointAuth> {
  INSTANCE;

  @Override
  public EndpointAuth read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeEndpointAuth.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(EndpointAuth value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeEndpointAuth.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(EndpointAuth value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeEndpointAuth.INSTANCE.write(value, buf);
    }
  }
}



