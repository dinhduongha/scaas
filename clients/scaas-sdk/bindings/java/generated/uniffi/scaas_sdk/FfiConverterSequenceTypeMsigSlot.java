package uniffi.scaas_sdk;


public enum FfiConverterSequenceTypeMsigSlot implements FfiConverterRustBuffer<java.util.List<MsigSlot>> {
  INSTANCE;

  @Override
  public java.util.List<MsigSlot> read(java.nio.ByteBuffer buf) {
    int len = buf.getInt();
    return java.util.stream.IntStream.range(0, len).mapToObj(_i -> FfiConverterTypeMsigSlot.INSTANCE.read(buf)).toList();
  }

  @Override
  public long allocationSize(java.util.List<MsigSlot> value) {
    long sizeForLength = 4L;
    long sizeForItems = value.stream().mapToLong(inner -> FfiConverterTypeMsigSlot.INSTANCE.allocationSize(inner)).sum();
    return sizeForLength + sizeForItems;
  }

  @Override
  public void write(java.util.List<MsigSlot> value, java.nio.ByteBuffer buf) {
    buf.putInt(value.size());
    value.forEach(inner -> FfiConverterTypeMsigSlot.INSTANCE.write(inner, buf));
  }
}




