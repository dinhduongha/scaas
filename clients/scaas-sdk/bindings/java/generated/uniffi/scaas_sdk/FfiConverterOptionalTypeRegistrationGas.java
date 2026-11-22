package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeRegistrationGas implements FfiConverterRustBuffer<RegistrationGas> {
  INSTANCE;

  @Override
  public RegistrationGas read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeRegistrationGas.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(RegistrationGas value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeRegistrationGas.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(RegistrationGas value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeRegistrationGas.INSTANCE.write(value, buf);
    }
  }
}



