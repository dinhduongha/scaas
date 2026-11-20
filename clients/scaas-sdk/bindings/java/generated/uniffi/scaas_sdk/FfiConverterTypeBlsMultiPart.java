package uniffi.scaas_sdk;


public enum FfiConverterTypeBlsMultiPart implements FfiConverterRustBuffer<BlsMultiPart> {
  INSTANCE;

  @Override
  public BlsMultiPart read(java.nio.ByteBuffer buf) {
    return new BlsMultiPart(
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(BlsMultiPart value) {
      return (
            FfiConverterByte.INSTANCE.allocationSize(value.index()) +
            FfiConverterString.INSTANCE.allocationSize(value.signature())
      );
  }

  @Override
  public void write(BlsMultiPart value, java.nio.ByteBuffer buf) {
      FfiConverterByte.INSTANCE.write(value.index(), buf);
      FfiConverterString.INSTANCE.write(value.signature(), buf);
  }
}



