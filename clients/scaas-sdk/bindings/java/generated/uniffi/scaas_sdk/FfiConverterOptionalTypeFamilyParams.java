package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeFamilyParams implements FfiConverterRustBuffer<FamilyParams> {
  INSTANCE;

  @Override
  public FamilyParams read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeFamilyParams.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(FamilyParams value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeFamilyParams.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(FamilyParams value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeFamilyParams.INSTANCE.write(value, buf);
    }
  }
}



