package uniffi.scaas_sdk;


public enum FfiConverterTypePayBody implements FfiConverterRustBuffer<PayBody> {
    INSTANCE;

    @Override
    public PayBody read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new PayBody.None();
        case 2 -> new PayBody.Note(FfiConverterString.INSTANCE.read(buf)
          );
        case 3 -> new PayBody.CreditorRef(FfiConverterString.INSTANCE.read(buf),
          FfiConverterLong.INSTANCE.read(buf)
          );
        case 4 -> new PayBody.BoundCall(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 5 -> new PayBody.Ciphertext(FfiConverterString.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(PayBody value) {
        return switch (value) {
          case PayBody.None() ->
            (4L);
          case PayBody.Note(var note) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(note));
          case PayBody.CreditorRef(var creditorRef, var dueDate) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(creditorRef)
            + FfiConverterLong.INSTANCE.allocationSize(dueDate));
          case PayBody.BoundCall(var chainId, var target, var callHash) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(chainId)
            + FfiConverterString.INSTANCE.allocationSize(target)
            + FfiConverterString.INSTANCE.allocationSize(callHash));
          case PayBody.Ciphertext(var ciphertext) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(ciphertext));
        };
    }

    @Override
    public void write(PayBody value, java.nio.ByteBuffer buf) {
      switch (value) {
        case PayBody.None() -> {
          buf.putInt(1);
        }
        case PayBody.Note(var note) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(note, buf);
        }
        case PayBody.CreditorRef(var creditorRef, var dueDate) -> {
          buf.putInt(3);
          FfiConverterString.INSTANCE.write(creditorRef, buf);
          FfiConverterLong.INSTANCE.write(dueDate, buf);
        }
        case PayBody.BoundCall(var chainId, var target, var callHash) -> {
          buf.putInt(4);
          FfiConverterString.INSTANCE.write(chainId, buf);
          FfiConverterString.INSTANCE.write(target, buf);
          FfiConverterString.INSTANCE.write(callHash, buf);
        }
        case PayBody.Ciphertext(var ciphertext) -> {
          buf.putInt(5);
          FfiConverterString.INSTANCE.write(ciphertext, buf);
        }
      };
    }
}





