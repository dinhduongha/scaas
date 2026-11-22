package uniffi.scaas_sdk;


public enum FfiConverterTypeRestore implements FfiConverterRustBuffer<Restore> {
  INSTANCE;

  @Override
  public Restore read(java.nio.ByteBuffer buf) {
    return new Restore(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInt16Array.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Restore value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterInt16Array.INSTANCE.allocationSize(value.kinds()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.gap())
      );
  }

  @Override
  public void write(Restore value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterInt16Array.INSTANCE.write(value.kinds(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterInteger.INSTANCE.write(value.gap(), buf);
  }
}



