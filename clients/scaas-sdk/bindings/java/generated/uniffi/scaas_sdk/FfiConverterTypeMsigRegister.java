package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigRegister implements FfiConverterRustBuffer<MsigRegister> {
  INSTANCE;

  @Override
  public MsigRegister read(java.nio.ByteBuffer buf) {
    return new MsigRegister(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeMsigStructureArgs.INSTANCE.read(buf),
      FfiConverterSequenceTypeMsigSlot.INSTANCE.read(buf),
      FfiConverterTypeKeyRef.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MsigRegister value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterTypeMsigStructureArgs.INSTANCE.allocationSize(value.structure()) +
            FfiConverterSequenceTypeMsigSlot.INSTANCE.allocationSize(value.slots()) +
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.payer())
      );
  }

  @Override
  public void write(MsigRegister value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterTypeMsigStructureArgs.INSTANCE.write(value.structure(), buf);
      FfiConverterSequenceTypeMsigSlot.INSTANCE.write(value.slots(), buf);
      FfiConverterTypeKeyRef.INSTANCE.write(value.payer(), buf);
  }
}



