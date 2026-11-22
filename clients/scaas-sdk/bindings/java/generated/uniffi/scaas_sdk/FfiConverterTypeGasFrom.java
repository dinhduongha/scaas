package uniffi.scaas_sdk;


public enum FfiConverterTypeGasFrom implements FfiConverterRustBuffer<GasFrom> {
    INSTANCE;

    @Override
    public GasFrom read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new GasFrom.Chain();
        case 2 -> new GasFrom.Module(FfiConverterString.INSTANCE.read(buf)
          );
        case 3 -> new GasFrom.Reference();
        case 4 -> new GasFrom.App();
        case 5 -> new GasFrom.Estimate();
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(GasFrom value) {
        return switch (value) {
          case GasFrom.Chain() ->
            (4L);
          case GasFrom.Module(var v1) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(v1));
          case GasFrom.Reference() ->
            (4L);
          case GasFrom.App() ->
            (4L);
          case GasFrom.Estimate() ->
            (4L);
        };
    }

    @Override
    public void write(GasFrom value, java.nio.ByteBuffer buf) {
      switch (value) {
        case GasFrom.Chain() -> {
          buf.putInt(1);
        }
        case GasFrom.Module(var v1) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(v1, buf);
        }
        case GasFrom.Reference() -> {
          buf.putInt(3);
        }
        case GasFrom.App() -> {
          buf.putInt(4);
        }
        case GasFrom.Estimate() -> {
          buf.putInt(5);
        }
      };
    }
}





