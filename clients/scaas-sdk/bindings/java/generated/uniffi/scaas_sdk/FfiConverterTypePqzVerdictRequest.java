package uniffi.scaas_sdk;


public enum FfiConverterTypePqzVerdictRequest implements FfiConverterRustBuffer<PqzVerdictRequest> {
  INSTANCE;

  @Override
  public PqzVerdictRequest read(java.nio.ByteBuffer buf) {
    return new PqzVerdictRequest(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeValue.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PqzVerdictRequest value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterTypeValue.INSTANCE.allocationSize(value.op()) +
            FfiConverterString.INSTANCE.allocationSize(value.statement()) +
            FfiConverterString.INSTANCE.allocationSize(value.proof())
      );
  }

  @Override
  public void write(PqzVerdictRequest value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterTypeValue.INSTANCE.write(value.op(), buf);
      FfiConverterString.INSTANCE.write(value.statement(), buf);
      FfiConverterString.INSTANCE.write(value.proof(), buf);
  }
}



