package uniffi.scaas_sdk;


public enum FfiConverterTypeRegistrationState implements FfiConverterRustBuffer<RegistrationState> {
  INSTANCE;

  @Override
  public RegistrationState read(java.nio.ByteBuffer buf) {
    return new RegistrationState(
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(RegistrationState value) {
      return (
            FfiConverterBoolean.INSTANCE.allocationSize(value.registered()) +
            FfiConverterString.INSTANCE.allocationSize(value.kemPkHash()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.kemStored()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.pqzPopStored()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.pqzProven())
      );
  }

  @Override
  public void write(RegistrationState value, java.nio.ByteBuffer buf) {
      FfiConverterBoolean.INSTANCE.write(value.registered(), buf);
      FfiConverterString.INSTANCE.write(value.kemPkHash(), buf);
      FfiConverterBoolean.INSTANCE.write(value.kemStored(), buf);
      FfiConverterBoolean.INSTANCE.write(value.pqzPopStored(), buf);
      FfiConverterBoolean.INSTANCE.write(value.pqzProven(), buf);
  }
}



