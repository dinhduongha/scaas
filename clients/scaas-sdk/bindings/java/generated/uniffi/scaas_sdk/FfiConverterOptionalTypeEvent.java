package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeEvent implements FfiConverterRustBuffer<Event> {
  INSTANCE;

  @Override
  public Event read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeEvent.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(Event value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeEvent.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(Event value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeEvent.INSTANCE.write(value, buf);
    }
  }
}



