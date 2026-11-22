package uniffi.scaas_sdk;


public enum FfiConverterTypeUnlock implements FfiConverterRustBuffer<Unlock> {
    INSTANCE;

    @Override
    public Unlock read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new Unlock.Passphrase(FfiConverterTypeSecretBytes.INSTANCE.read(buf)
          );
        case 2 -> new Unlock.Passkey();
        case 3 -> new Unlock.Platform();
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(Unlock value) {
        return switch (value) {
          case Unlock.Passphrase(var v1) ->
            (4L
            + FfiConverterTypeSecretBytes.INSTANCE.allocationSize(v1));
          case Unlock.Passkey() ->
            (4L);
          case Unlock.Platform() ->
            (4L);
        };
    }

    @Override
    public void write(Unlock value, java.nio.ByteBuffer buf) {
      switch (value) {
        case Unlock.Passphrase(var v1) -> {
          buf.putInt(1);
          FfiConverterTypeSecretBytes.INSTANCE.write(v1, buf);
        }
        case Unlock.Passkey() -> {
          buf.putInt(2);
        }
        case Unlock.Platform() -> {
          buf.putInt(3);
        }
      };
    }
}





