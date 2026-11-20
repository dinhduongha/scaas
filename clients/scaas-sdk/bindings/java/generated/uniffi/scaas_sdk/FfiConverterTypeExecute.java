package uniffi.scaas_sdk;


public enum FfiConverterTypeExecute implements FfiConverterRustBuffer<Execute> {
  INSTANCE;

  @Override
  public Execute read(java.nio.ByteBuffer buf) {
    return new Execute(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeExecuteCall.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Execute value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.wallet()) +
            FfiConverterTypeExecuteCall.INSTANCE.allocationSize(value.call()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(Execute value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.wallet(), buf);
      FfiConverterTypeExecuteCall.INSTANCE.write(value.call(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



