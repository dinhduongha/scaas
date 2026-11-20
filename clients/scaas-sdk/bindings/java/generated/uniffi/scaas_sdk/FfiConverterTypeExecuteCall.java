package uniffi.scaas_sdk;


public enum FfiConverterTypeExecuteCall implements FfiConverterRustBuffer<ExecuteCall> {
    INSTANCE;

    @Override
    public ExecuteCall read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new ExecuteCall.Transfer(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 2 -> new ExecuteCall.Opaque(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterOptionalTypeAllowOpaqueCall.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(ExecuteCall value) {
        return switch (value) {
          case ExecuteCall.Transfer(var token, var to, var amount) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(token)
            + FfiConverterString.INSTANCE.allocationSize(to)
            + FfiConverterString.INSTANCE.allocationSize(amount));
          case ExecuteCall.Opaque(var target, var value_, var data, var allow) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(target)
            + FfiConverterString.INSTANCE.allocationSize(value_)
            + FfiConverterString.INSTANCE.allocationSize(data)
            + FfiConverterOptionalTypeAllowOpaqueCall.INSTANCE.allocationSize(allow));
        };
    }

    @Override
    public void write(ExecuteCall value, java.nio.ByteBuffer buf) {
      switch (value) {
        case ExecuteCall.Transfer(var token, var to, var amount) -> {
          buf.putInt(1);
          FfiConverterString.INSTANCE.write(token, buf);
          FfiConverterString.INSTANCE.write(to, buf);
          FfiConverterString.INSTANCE.write(amount, buf);
        }
        case ExecuteCall.Opaque(var target, var value_, var data, var allow) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(target, buf);
          FfiConverterString.INSTANCE.write(value_, buf);
          FfiConverterString.INSTANCE.write(data, buf);
          FfiConverterOptionalTypeAllowOpaqueCall.INSTANCE.write(allow, buf);
        }
      };
    }
}





