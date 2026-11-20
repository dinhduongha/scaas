package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherLeg implements FfiConverterRustBuffer<ZetherLeg> {
  INSTANCE;

  @Override
  public ZetherLeg read(java.nio.ByteBuffer buf) {
    return new ZetherLeg(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherLeg value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.toUa()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount())
      );
  }

  @Override
  public void write(ZetherLeg value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.toUa(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
  }
}



