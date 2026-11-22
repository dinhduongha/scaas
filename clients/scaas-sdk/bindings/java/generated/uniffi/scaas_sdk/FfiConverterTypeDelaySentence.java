package uniffi.scaas_sdk;


public enum FfiConverterTypeDelaySentence implements FfiConverterRustBuffer<DelaySentence> {
    INSTANCE;

    @Override
    public DelaySentence read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new DelaySentence.AtOnce();
        case 2 -> new DelaySentence.After(FfiConverterLong.INSTANCE.read(buf)
          );
        case 3 -> new DelaySentence.SingleKey();
        case 4 -> new DelaySentence.Locked();
        case 5 -> new DelaySentence.NoDelay();
        case 6 -> new DelaySentence.Unknown();
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(DelaySentence value) {
        return switch (value) {
          case DelaySentence.AtOnce() ->
            (4L);
          case DelaySentence.After(var delay) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(delay));
          case DelaySentence.SingleKey() ->
            (4L);
          case DelaySentence.Locked() ->
            (4L);
          case DelaySentence.NoDelay() ->
            (4L);
          case DelaySentence.Unknown() ->
            (4L);
        };
    }

    @Override
    public void write(DelaySentence value, java.nio.ByteBuffer buf) {
      switch (value) {
        case DelaySentence.AtOnce() -> {
          buf.putInt(1);
        }
        case DelaySentence.After(var delay) -> {
          buf.putInt(2);
          FfiConverterLong.INSTANCE.write(delay, buf);
        }
        case DelaySentence.SingleKey() -> {
          buf.putInt(3);
        }
        case DelaySentence.Locked() -> {
          buf.putInt(4);
        }
        case DelaySentence.NoDelay() -> {
          buf.putInt(5);
        }
        case DelaySentence.Unknown() -> {
          buf.putInt(6);
        }
      };
    }
}





