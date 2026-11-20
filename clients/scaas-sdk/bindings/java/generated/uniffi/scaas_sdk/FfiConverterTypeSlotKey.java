package uniffi.scaas_sdk;


public enum FfiConverterTypeSlotKey implements FfiConverterRustBuffer<SlotKey> {
    INSTANCE;

    @Override
    public SlotKey read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new SlotKey.Ua(FfiConverterString.INSTANCE.read(buf),
          FfiConverterShort.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf)
          );
        case 2 -> new SlotKey.Native(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf)
          );
        case 3 -> new SlotKey.Imported(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf)
          );
        case 4 -> new SlotKey.Key(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 5 -> new SlotKey.Msig(FfiConverterString.INSTANCE.read(buf)
          );
        case 6 -> new SlotKey.BlsMulti(FfiConverterString.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(SlotKey value) {
        return switch (value) {
          case SlotKey.Ua(var seed, var kind, var account, var index) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterShort.INSTANCE.allocationSize(kind)
            + FfiConverterInteger.INSTANCE.allocationSize(account)
            + FfiConverterInteger.INSTANCE.allocationSize(index));
          case SlotKey.Native(var seed, var network, var index) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterString.INSTANCE.allocationSize(network)
            + FfiConverterInteger.INSTANCE.allocationSize(index));
          case SlotKey.Imported(var seed, var network, var index) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterString.INSTANCE.allocationSize(network)
            + FfiConverterInteger.INSTANCE.allocationSize(index));
          case SlotKey.Key(var seed, var id) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterString.INSTANCE.allocationSize(id));
          case SlotKey.Msig(var ua) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(ua));
          case SlotKey.BlsMulti(var seed, var account, var index, var keyData) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterInteger.INSTANCE.allocationSize(account)
            + FfiConverterInteger.INSTANCE.allocationSize(index)
            + FfiConverterString.INSTANCE.allocationSize(keyData));
        };
    }

    @Override
    public void write(SlotKey value, java.nio.ByteBuffer buf) {
      switch (value) {
        case SlotKey.Ua(var seed, var kind, var account, var index) -> {
          buf.putInt(1);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterShort.INSTANCE.write(kind, buf);
          FfiConverterInteger.INSTANCE.write(account, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
        }
        case SlotKey.Native(var seed, var network, var index) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterString.INSTANCE.write(network, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
        }
        case SlotKey.Imported(var seed, var network, var index) -> {
          buf.putInt(3);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterString.INSTANCE.write(network, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
        }
        case SlotKey.Key(var seed, var id) -> {
          buf.putInt(4);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterString.INSTANCE.write(id, buf);
        }
        case SlotKey.Msig(var ua) -> {
          buf.putInt(5);
          FfiConverterString.INSTANCE.write(ua, buf);
        }
        case SlotKey.BlsMulti(var seed, var account, var index, var keyData) -> {
          buf.putInt(6);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterInteger.INSTANCE.write(account, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
          FfiConverterString.INSTANCE.write(keyData, buf);
        }
      };
    }
}





