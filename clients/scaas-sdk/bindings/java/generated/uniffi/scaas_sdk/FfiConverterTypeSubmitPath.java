package uniffi.scaas_sdk;


public enum FfiConverterTypeSubmitPath implements FfiConverterRustBuffer<SubmitPath> {
    INSTANCE;

    @Override
    public SubmitPath read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new SubmitPath.Auto(FfiConverterOptionalTypeKeyRef.INSTANCE.read(buf)
          );
        case 2 -> new SubmitPath.Gateway();
        case 3 -> new SubmitPath.SelfRelay(FfiConverterTypeKeyRef.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(SubmitPath value) {
        return switch (value) {
          case SubmitPath.Auto(var payer) ->
            (4L
            + FfiConverterOptionalTypeKeyRef.INSTANCE.allocationSize(payer));
          case SubmitPath.Gateway() ->
            (4L);
          case SubmitPath.SelfRelay(var payer) ->
            (4L
            + FfiConverterTypeKeyRef.INSTANCE.allocationSize(payer));
        };
    }

    @Override
    public void write(SubmitPath value, java.nio.ByteBuffer buf) {
      switch (value) {
        case SubmitPath.Auto(var payer) -> {
          buf.putInt(1);
          FfiConverterOptionalTypeKeyRef.INSTANCE.write(payer, buf);
        }
        case SubmitPath.Gateway() -> {
          buf.putInt(2);
        }
        case SubmitPath.SelfRelay(var payer) -> {
          buf.putInt(3);
          FfiConverterTypeKeyRef.INSTANCE.write(payer, buf);
        }
      };
    }
}





