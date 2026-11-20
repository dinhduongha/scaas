package uniffi.scaas_sdk;


public enum FfiConverterTypeOpState implements FfiConverterRustBuffer<OpState> {
    INSTANCE;

    @Override
    public OpState read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new OpState.Landed(FfiConverterLong.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 2 -> new OpState.Consumed();
        case 3 -> new OpState.Reverted(FfiConverterLong.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 4 -> new OpState.Expired();
        case 5 -> new OpState.InFlight(FfiConverterTypeInFlight.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(OpState value) {
        return switch (value) {
          case OpState.Landed(var block, var hash) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(block)
            + FfiConverterString.INSTANCE.allocationSize(hash));
          case OpState.Consumed() ->
            (4L);
          case OpState.Reverted(var block, var hash) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(block)
            + FfiConverterString.INSTANCE.allocationSize(hash));
          case OpState.Expired() ->
            (4L);
          case OpState.InFlight(var detail) ->
            (4L
            + FfiConverterTypeInFlight.INSTANCE.allocationSize(detail));
        };
    }

    @Override
    public void write(OpState value, java.nio.ByteBuffer buf) {
      switch (value) {
        case OpState.Landed(var block, var hash) -> {
          buf.putInt(1);
          FfiConverterLong.INSTANCE.write(block, buf);
          FfiConverterString.INSTANCE.write(hash, buf);
        }
        case OpState.Consumed() -> {
          buf.putInt(2);
        }
        case OpState.Reverted(var block, var hash) -> {
          buf.putInt(3);
          FfiConverterLong.INSTANCE.write(block, buf);
          FfiConverterString.INSTANCE.write(hash, buf);
        }
        case OpState.Expired() -> {
          buf.putInt(4);
        }
        case OpState.InFlight(var detail) -> {
          buf.putInt(5);
          FfiConverterTypeInFlight.INSTANCE.write(detail, buf);
        }
      };
    }
}





