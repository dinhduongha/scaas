package uniffi.scaas_sdk;


public enum FfiConverterTypeEvent implements FfiConverterRustBuffer<Event> {
    INSTANCE;

    @Override
    public Event read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new Event.SeedUnlocked(FfiConverterString.INSTANCE.read(buf)
          );
        case 2 -> new Event.SeedLocked(FfiConverterString.INSTANCE.read(buf)
          );
        case 3 -> new Event.KeystoreChanged(FfiConverterLong.INSTANCE.read(buf)
          );
        case 4 -> new Event.KeystoreMismatch(FfiConverterString.INSTANCE.read(buf)
          );
        case 5 -> new Event.KeystoreRollback();
        case 6 -> new Event.HiddenOpsAbandoned(FfiConverterInteger.INSTANCE.read(buf)
          );
        case 7 -> new Event.Lagged(FfiConverterLong.INSTANCE.read(buf)
          );
        case 8 -> new Event.OpState(FfiConverterString.INSTANCE.read(buf),
          FfiConverterTypeOpState.INSTANCE.read(buf)
          );
        case 9 -> new Event.BalanceChanged(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 10 -> new Event.HistoryAdded(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterSequenceTypeHistoryItem.INSTANCE.read(buf)
          );
        case 11 -> new Event.StateChanged(FfiConverterLong.INSTANCE.read(buf)
          );
        case 12 -> new Event.ProfileIndexMismatch();
        case 13 -> new Event.ProfileRollback();
        case 14 -> new Event.ProfileDamaged();
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(Event value) {
        return switch (value) {
          case Event.SeedUnlocked(var seed) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed));
          case Event.SeedLocked(var seed) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed));
          case Event.KeystoreChanged(var rev) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(rev));
          case Event.KeystoreMismatch(var seed) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(seed));
          case Event.KeystoreRollback() ->
            (4L);
          case Event.HiddenOpsAbandoned(var count) ->
            (4L
            + FfiConverterInteger.INSTANCE.allocationSize(count));
          case Event.Lagged(var missed) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(missed));
          case Event.OpState(var op, var state) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(op)
            + FfiConverterTypeOpState.INSTANCE.allocationSize(state));
          case Event.BalanceChanged(var account, var chain, var token) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(account)
            + FfiConverterString.INSTANCE.allocationSize(chain)
            + FfiConverterString.INSTANCE.allocationSize(token));
          case Event.HistoryAdded(var account, var chain, var items) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(account)
            + FfiConverterString.INSTANCE.allocationSize(chain)
            + FfiConverterSequenceTypeHistoryItem.INSTANCE.allocationSize(items));
          case Event.StateChanged(var rev) ->
            (4L
            + FfiConverterLong.INSTANCE.allocationSize(rev));
          case Event.ProfileIndexMismatch() ->
            (4L);
          case Event.ProfileRollback() ->
            (4L);
          case Event.ProfileDamaged() ->
            (4L);
        };
    }

    @Override
    public void write(Event value, java.nio.ByteBuffer buf) {
      switch (value) {
        case Event.SeedUnlocked(var seed) -> {
          buf.putInt(1);
          FfiConverterString.INSTANCE.write(seed, buf);
        }
        case Event.SeedLocked(var seed) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(seed, buf);
        }
        case Event.KeystoreChanged(var rev) -> {
          buf.putInt(3);
          FfiConverterLong.INSTANCE.write(rev, buf);
        }
        case Event.KeystoreMismatch(var seed) -> {
          buf.putInt(4);
          FfiConverterString.INSTANCE.write(seed, buf);
        }
        case Event.KeystoreRollback() -> {
          buf.putInt(5);
        }
        case Event.HiddenOpsAbandoned(var count) -> {
          buf.putInt(6);
          FfiConverterInteger.INSTANCE.write(count, buf);
        }
        case Event.Lagged(var missed) -> {
          buf.putInt(7);
          FfiConverterLong.INSTANCE.write(missed, buf);
        }
        case Event.OpState(var op, var state) -> {
          buf.putInt(8);
          FfiConverterString.INSTANCE.write(op, buf);
          FfiConverterTypeOpState.INSTANCE.write(state, buf);
        }
        case Event.BalanceChanged(var account, var chain, var token) -> {
          buf.putInt(9);
          FfiConverterString.INSTANCE.write(account, buf);
          FfiConverterString.INSTANCE.write(chain, buf);
          FfiConverterString.INSTANCE.write(token, buf);
        }
        case Event.HistoryAdded(var account, var chain, var items) -> {
          buf.putInt(10);
          FfiConverterString.INSTANCE.write(account, buf);
          FfiConverterString.INSTANCE.write(chain, buf);
          FfiConverterSequenceTypeHistoryItem.INSTANCE.write(items, buf);
        }
        case Event.StateChanged(var rev) -> {
          buf.putInt(11);
          FfiConverterLong.INSTANCE.write(rev, buf);
        }
        case Event.ProfileIndexMismatch() -> {
          buf.putInt(12);
        }
        case Event.ProfileRollback() -> {
          buf.putInt(13);
        }
        case Event.ProfileDamaged() -> {
          buf.putInt(14);
        }
      };
    }
}





