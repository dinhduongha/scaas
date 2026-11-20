package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigSlotValue implements FfiConverterRustBuffer<MsigSlotValue> {
    INSTANCE;

    @Override
    public MsigSlotValue read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new MsigSlotValue.Member(FfiConverterShort.INSTANCE.read(buf),
          FfiConverterTypeSlotKey.INSTANCE.read(buf)
          );
        case 2 -> new MsigSlotValue.Msig(FfiConverterShort.INSTANCE.read(buf),
          FfiConverterSequenceTypeMsigLeafValue.INSTANCE.read(buf)
          );
        case 3 -> new MsigSlotValue.Signed(FfiConverterShort.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(MsigSlotValue value) {
        return switch (value) {
          case MsigSlotValue.Member(var index, var key) ->
            (4L
            + FfiConverterShort.INSTANCE.allocationSize(index)
            + FfiConverterTypeSlotKey.INSTANCE.allocationSize(key));
          case MsigSlotValue.Msig(var index, var members) ->
            (4L
            + FfiConverterShort.INSTANCE.allocationSize(index)
            + FfiConverterSequenceTypeMsigLeafValue.INSTANCE.allocationSize(members));
          case MsigSlotValue.Signed(var index, var member) ->
            (4L
            + FfiConverterShort.INSTANCE.allocationSize(index)
            + FfiConverterString.INSTANCE.allocationSize(member));
        };
    }

    @Override
    public void write(MsigSlotValue value, java.nio.ByteBuffer buf) {
      switch (value) {
        case MsigSlotValue.Member(var index, var key) -> {
          buf.putInt(1);
          FfiConverterShort.INSTANCE.write(index, buf);
          FfiConverterTypeSlotKey.INSTANCE.write(key, buf);
        }
        case MsigSlotValue.Msig(var index, var members) -> {
          buf.putInt(2);
          FfiConverterShort.INSTANCE.write(index, buf);
          FfiConverterSequenceTypeMsigLeafValue.INSTANCE.write(members, buf);
        }
        case MsigSlotValue.Signed(var index, var member) -> {
          buf.putInt(3);
          FfiConverterShort.INSTANCE.write(index, buf);
          FfiConverterString.INSTANCE.write(member, buf);
        }
      };
    }
}





