package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeKemRecord implements FfiConverterRustBuffer<KemRecord> {
  INSTANCE;

  @Override
  public KemRecord read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeKemRecord.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(KemRecord value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeKemRecord.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(KemRecord value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeKemRecord.INSTANCE.write(value, buf);
    }
  }
}



