package uniffi.scaas_sdk;


public enum FfiConverterTypeEndpointAuth implements FfiConverterRustBuffer<EndpointAuth> {
    INSTANCE;

    @Override
    public EndpointAuth read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new EndpointAuth.Bearer(FfiConverterTypeSecret.INSTANCE.read(buf)
          );
        case 2 -> new EndpointAuth.Hmac(FfiConverterTypeSecret.INSTANCE.read(buf)
          );
        case 3 -> new EndpointAuth.Header(FfiConverterString.INSTANCE.read(buf),
          FfiConverterTypeSecret.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(EndpointAuth value) {
        return switch (value) {
          case EndpointAuth.Bearer(var v1) ->
            (4L
            + FfiConverterTypeSecret.INSTANCE.allocationSize(v1));
          case EndpointAuth.Hmac(var v1) ->
            (4L
            + FfiConverterTypeSecret.INSTANCE.allocationSize(v1));
          case EndpointAuth.Header(var name, var value_) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(name)
            + FfiConverterTypeSecret.INSTANCE.allocationSize(value_));
        };
    }

    @Override
    public void write(EndpointAuth value, java.nio.ByteBuffer buf) {
      switch (value) {
        case EndpointAuth.Bearer(var v1) -> {
          buf.putInt(1);
          FfiConverterTypeSecret.INSTANCE.write(v1, buf);
        }
        case EndpointAuth.Hmac(var v1) -> {
          buf.putInt(2);
          FfiConverterTypeSecret.INSTANCE.write(v1, buf);
        }
        case EndpointAuth.Header(var name, var value_) -> {
          buf.putInt(3);
          FfiConverterString.INSTANCE.write(name, buf);
          FfiConverterTypeSecret.INSTANCE.write(value_, buf);
        }
      };
    }
}





