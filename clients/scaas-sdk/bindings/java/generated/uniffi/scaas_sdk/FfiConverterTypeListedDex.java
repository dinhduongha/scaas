package uniffi.scaas_sdk;


public enum FfiConverterTypeListedDex implements FfiConverterRustBuffer<ListedDex> {
  INSTANCE;

  @Override
  public ListedDex read(java.nio.ByteBuffer buf) {
    return new ListedDex(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterSequenceTypePositionReader.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ListedDex value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.address()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.liquidity()) +
            FfiConverterSequenceTypePositionReader.INSTANCE.allocationSize(value.positionReaders())
      );
  }

  @Override
  public void write(ListedDex value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.address(), buf);
      FfiConverterBoolean.INSTANCE.write(value.liquidity(), buf);
      FfiConverterSequenceTypePositionReader.INSTANCE.write(value.positionReaders(), buf);
  }
}



