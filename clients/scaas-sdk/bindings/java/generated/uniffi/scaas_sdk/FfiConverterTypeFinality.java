package uniffi.scaas_sdk;


public enum FfiConverterTypeFinality implements FfiConverterRustBuffer<Finality> {
    INSTANCE;

    @Override
    public Finality read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new Finality.Finalized();
        case 2 -> new Finality.Depth(FfiConverterLong.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(Finality value) {
        return switch (value) {
          case Finality.Finalized() ->
            (4L);
          case Finality.Depth(var v1) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(v1));
        };
    }

    @Override
    public void write(Finality value, java.nio.ByteBuffer buf) {
      switch (value) {
        case Finality.Finalized() -> {
          buf.putInt(1);
        }
        case Finality.Depth(var v1) -> {
          buf.putInt(2);
          FfiConverterLong.INSTANCE.write(v1, buf);
        }
      };
    }
}





