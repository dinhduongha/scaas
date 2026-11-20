package uniffi.scaas_sdk;


public enum FfiConverterTypeCreate3Preview implements FfiConverterRustBuffer<Create3Preview> {
  INSTANCE;

  @Override
  public Create3Preview read(java.nio.ByteBuffer buf) {
    return new Create3Preview(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Create3Preview value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.s()) +
            FfiConverterString.INSTANCE.allocationSize(value.proxy()) +
            FfiConverterString.INSTANCE.allocationSize(value.instance())
      );
  }

  @Override
  public void write(Create3Preview value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.s(), buf);
      FfiConverterString.INSTANCE.write(value.proxy(), buf);
      FfiConverterString.INSTANCE.write(value.instance(), buf);
  }
}



