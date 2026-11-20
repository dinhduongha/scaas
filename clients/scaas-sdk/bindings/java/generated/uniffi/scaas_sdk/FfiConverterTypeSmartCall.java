package uniffi.scaas_sdk;


public enum FfiConverterTypeSmartCall implements FfiConverterRustBuffer<SmartCall> {
    INSTANCE;

    @Override
    public SmartCall read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new SmartCall.Transfer(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 2 -> new SmartCall.InitiateRecovery(FfiConverterString.INSTANCE.read(buf),
          FfiConverterTypeSubjectKeyArgs.INSTANCE.read(buf)
          );
        case 3 -> new SmartCall.Opaque(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterOptionalTypeAllowOpaqueCall.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(SmartCall value) {
        return switch (value) {
          case SmartCall.Transfer(var token, var to, var amount) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(token)
            + FfiConverterString.INSTANCE.allocationSize(to)
            + FfiConverterString.INSTANCE.allocationSize(amount));
          case SmartCall.InitiateRecovery(var account, var key) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(account)
            + FfiConverterTypeSubjectKeyArgs.INSTANCE.allocationSize(key));
          case SmartCall.Opaque(var target, var value_, var data, var allow) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(target)
            + FfiConverterString.INSTANCE.allocationSize(value_)
            + FfiConverterString.INSTANCE.allocationSize(data)
            + FfiConverterOptionalTypeAllowOpaqueCall.INSTANCE.allocationSize(allow));
        };
    }

    @Override
    public void write(SmartCall value, java.nio.ByteBuffer buf) {
      switch (value) {
        case SmartCall.Transfer(var token, var to, var amount) -> {
          buf.putInt(1);
          FfiConverterString.INSTANCE.write(token, buf);
          FfiConverterString.INSTANCE.write(to, buf);
          FfiConverterString.INSTANCE.write(amount, buf);
        }
        case SmartCall.InitiateRecovery(var account, var key) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(account, buf);
          FfiConverterTypeSubjectKeyArgs.INSTANCE.write(key, buf);
        }
        case SmartCall.Opaque(var target, var value_, var data, var allow) -> {
          buf.putInt(3);
          FfiConverterString.INSTANCE.write(target, buf);
          FfiConverterString.INSTANCE.write(value_, buf);
          FfiConverterString.INSTANCE.write(data, buf);
          FfiConverterOptionalTypeAllowOpaqueCall.INSTANCE.write(allow, buf);
        }
      };
    }
}





