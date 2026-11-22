package uniffi.scaas_sdk;


public enum FfiConverterTypeRescueOp implements FfiConverterRustBuffer<RescueOp> {
    INSTANCE;

    @Override
    public RescueOp read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new RescueOp.SetRescuer(FfiConverterLong.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 2 -> new RescueOp.RotateAdmin(FfiConverterLong.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(RescueOp value) {
        return switch (value) {
          case RescueOp.SetRescuer(var seq, var newRescuer) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(seq)
            + FfiConverterString.INSTANCE.allocationSize(newRescuer));
          case RescueOp.RotateAdmin(var seq, var newAdmin) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(seq)
            + FfiConverterString.INSTANCE.allocationSize(newAdmin));
        };
    }

    @Override
    public void write(RescueOp value, java.nio.ByteBuffer buf) {
      switch (value) {
        case RescueOp.SetRescuer(var seq, var newRescuer) -> {
          buf.putInt(1);
          FfiConverterLong.INSTANCE.write(seq, buf);
          FfiConverterString.INSTANCE.write(newRescuer, buf);
        }
        case RescueOp.RotateAdmin(var seq, var newAdmin) -> {
          buf.putInt(2);
          FfiConverterLong.INSTANCE.write(seq, buf);
          FfiConverterString.INSTANCE.write(newAdmin, buf);
        }
      };
    }
}




