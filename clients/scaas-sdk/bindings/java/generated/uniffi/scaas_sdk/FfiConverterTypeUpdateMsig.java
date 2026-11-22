package uniffi.scaas_sdk;


public enum FfiConverterTypeUpdateMsig implements FfiConverterRustBuffer<UpdateMsig> {
  INSTANCE;

  @Override
  public UpdateMsig read(java.nio.ByteBuffer buf) {
    return new UpdateMsig(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeMsigStructureArgs.INSTANCE.read(buf),
      FfiConverterInt16Array.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterSequenceTypeMsigSlot.INSTANCE.read(buf),
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(UpdateMsig value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.ua()) +
            FfiConverterTypeMsigStructureArgs.INSTANCE.allocationSize(value.structure()) +
            FfiConverterInt16Array.INSTANCE.allocationSize(value.enabled()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntilBlock()) +
            FfiConverterSequenceTypeMsigSlot.INSTANCE.allocationSize(value.slots()) +
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.payer()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.verifier()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.familyWithoutUpdate())
      );
  }

  @Override
  public void write(UpdateMsig value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.ua(), buf);
      FfiConverterTypeMsigStructureArgs.INSTANCE.write(value.structure(), buf);
      FfiConverterInt16Array.INSTANCE.write(value.enabled(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntilBlock(), buf);
      FfiConverterSequenceTypeMsigSlot.INSTANCE.write(value.slots(), buf);
      FfiConverterTypeKeyRef.INSTANCE.write(value.payer(), buf);
      FfiConverterBoolean.INSTANCE.write(value.verifier(), buf);
      FfiConverterBoolean.INSTANCE.write(value.familyWithoutUpdate(), buf);
  }
}



