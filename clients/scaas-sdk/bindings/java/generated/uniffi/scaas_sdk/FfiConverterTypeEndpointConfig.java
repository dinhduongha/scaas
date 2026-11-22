package uniffi.scaas_sdk;


public enum FfiConverterTypeEndpointConfig implements FfiConverterRustBuffer<EndpointConfig> {
  INSTANCE;

  @Override
  public EndpointConfig read(java.nio.ByteBuffer buf) {
    return new EndpointConfig(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeClass.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalTypeEndpointAuth.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(EndpointConfig value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.url()) +
            FfiConverterTypeClass.INSTANCE.allocationSize(value._class()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.label()) +
            FfiConverterOptionalTypeEndpointAuth.INSTANCE.allocationSize(value.auth())
      );
  }

  @Override
  public void write(EndpointConfig value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.url(), buf);
      FfiConverterTypeClass.INSTANCE.write(value._class(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.label(), buf);
      FfiConverterOptionalTypeEndpointAuth.INSTANCE.write(value.auth(), buf);
  }
}



