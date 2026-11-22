package uniffi.scaas_sdk;


public enum FfiConverterTypeAcceptMembership implements FfiConverterRustBuffer<AcceptMembership> {
  INSTANCE;

  @Override
  public AcceptMembership read(java.nio.ByteBuffer buf) {
    return new AcceptMembership(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeMsigSlot.INSTANCE.read(buf),
      FfiConverterTypeKeyRef.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AcceptMembership value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.ua()) +
            FfiConverterTypeMsigSlot.INSTANCE.allocationSize(value.slot()) +
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.payer())
      );
  }

  @Override
  public void write(AcceptMembership value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.ua(), buf);
      FfiConverterTypeMsigSlot.INSTANCE.write(value.slot(), buf);
      FfiConverterTypeKeyRef.INSTANCE.write(value.payer(), buf);
  }
}



