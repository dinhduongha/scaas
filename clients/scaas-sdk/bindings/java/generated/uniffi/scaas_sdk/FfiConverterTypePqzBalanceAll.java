package uniffi.scaas_sdk;


public enum FfiConverterTypePqzBalanceAll implements FfiConverterRustBuffer<PqzBalanceAll> {
  INSTANCE;

  @Override
  public PqzBalanceAll read(java.nio.ByteBuffer buf) {
    return new PqzBalanceAll(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterSequenceTypePqzBalance.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PqzBalanceAll value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterSequenceTypePqzBalance.INSTANCE.allocationSize(value.versions())
      );
  }

  @Override
  public void write(PqzBalanceAll value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterSequenceTypePqzBalance.INSTANCE.write(value.versions(), buf);
  }
}



