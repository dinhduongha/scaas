package uniffi.scaas_sdk;


public enum FfiConverterTypeSessionSet implements FfiConverterRustBuffer<SessionSet> {
  INSTANCE;

  @Override
  public SessionSet read(java.nio.ByteBuffer buf) {
    return new SessionSet(
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SessionSet value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.id())
      );
  }

  @Override
  public void write(SessionSet value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.id(), buf);
  }
}



