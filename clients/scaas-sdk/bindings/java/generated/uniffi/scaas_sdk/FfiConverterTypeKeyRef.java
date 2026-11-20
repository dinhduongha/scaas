package uniffi.scaas_sdk;


public enum FfiConverterTypeKeyRef implements FfiConverterRustBuffer<KeyRef> {
    INSTANCE;

    @Override
    public KeyRef read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new KeyRef.Ua(FfiConverterString.INSTANCE.read(buf),
          FfiConverterShort.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf)
          );
        case 2 -> new KeyRef.Native(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf)
          );
        case 3 -> new KeyRef.Imported(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf)
          );
        case 4 -> new KeyRef.Key(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 5 -> new KeyRef.Msig(FfiConverterString.INSTANCE.read(buf),
          FfiConverterSequenceTypeMsigSlot.INSTANCE.read(buf)
          );
        case 6 -> new KeyRef.BlsMulti(FfiConverterString.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf),
          FfiConverterInteger.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(KeyRef value) {
        return switch (value) {
          case KeyRef.Ua(var seed, var kind, var account, var index) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterShort.INSTANCE.allocationSize(kind)
            + FfiConverterInteger.INSTANCE.allocationSize(account)
            + FfiConverterInteger.INSTANCE.allocationSize(index));
          case KeyRef.Native(var seed, var network, var index) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterString.INSTANCE.allocationSize(network)
            + FfiConverterInteger.INSTANCE.allocationSize(index));
          case KeyRef.Imported(var seed, var network, var index) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterString.INSTANCE.allocationSize(network)
            + FfiConverterInteger.INSTANCE.allocationSize(index));
          case KeyRef.Key(var seed, var id) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterString.INSTANCE.allocationSize(id));
          case KeyRef.Msig(var ua, var slots) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(ua)
            + FfiConverterSequenceTypeMsigSlot.INSTANCE.allocationSize(slots));
          case KeyRef.BlsMulti(var seed, var account, var index, var keyData) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed)
            + FfiConverterInteger.INSTANCE.allocationSize(account)
            + FfiConverterInteger.INSTANCE.allocationSize(index)
            + FfiConverterString.INSTANCE.allocationSize(keyData));
        };
    }

    @Override
    public void write(KeyRef value, java.nio.ByteBuffer buf) {
      switch (value) {
        case KeyRef.Ua(var seed, var kind, var account, var index) -> {
          buf.putInt(1);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterShort.INSTANCE.write(kind, buf);
          FfiConverterInteger.INSTANCE.write(account, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
        }
        case KeyRef.Native(var seed, var network, var index) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterString.INSTANCE.write(network, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
        }
        case KeyRef.Imported(var seed, var network, var index) -> {
          buf.putInt(3);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterString.INSTANCE.write(network, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
        }
        case KeyRef.Key(var seed, var id) -> {
          buf.putInt(4);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterString.INSTANCE.write(id, buf);
        }
        case KeyRef.Msig(var ua, var slots) -> {
          buf.putInt(5);
          FfiConverterString.INSTANCE.write(ua, buf);
          FfiConverterSequenceTypeMsigSlot.INSTANCE.write(slots, buf);
        }
        case KeyRef.BlsMulti(var seed, var account, var index, var keyData) -> {
          buf.putInt(6);
          FfiConverterString.INSTANCE.write(seed, buf);
          FfiConverterInteger.INSTANCE.write(account, buf);
          FfiConverterInteger.INSTANCE.write(index, buf);
          FfiConverterString.INSTANCE.write(keyData, buf);
        }
      };
    }
}





