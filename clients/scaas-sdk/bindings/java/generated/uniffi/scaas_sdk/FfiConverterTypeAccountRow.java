package uniffi.scaas_sdk;


public enum FfiConverterTypeAccountRow implements FfiConverterRustBuffer<AccountRow> {
    INSTANCE;

    @Override
    public AccountRow read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new AccountRow.Ua(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterLong.INSTANCE.read(buf),
          FfiConverterLong.INSTANCE.read(buf),
          FfiConverterLong.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 2 -> new AccountRow.Native(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterLong.INSTANCE.read(buf),
          FfiConverterOptionalLong.INSTANCE.read(buf),
          FfiConverterOptionalLong.INSTANCE.read(buf),
          FfiConverterOptionalString.INSTANCE.read(buf),
          FfiConverterOptionalLong.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 3 -> new AccountRow.Key(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterLong.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterOptionalString.INSTANCE.read(buf),
          FfiConverterOptionalString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 4 -> new AccountRow.Watch(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(AccountRow value) {
        return switch (value) {
          case AccountRow.Ua(var id, var name, var kind, var account, var index, var ua) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(id)
            + FfiConverterString.INSTANCE.allocationSize(name)
            + FfiConverterLong.INSTANCE.allocationSize(kind)
            + FfiConverterLong.INSTANCE.allocationSize(account)
            + FfiConverterLong.INSTANCE.allocationSize(index)
            + FfiConverterString.INSTANCE.allocationSize(ua));
          case AccountRow.Native(var id, var name, var network, var index, var coinType, var change, var path, var ss58Prefix, var address) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(id)
            + FfiConverterString.INSTANCE.allocationSize(name)
            + FfiConverterString.INSTANCE.allocationSize(network)
            + FfiConverterLong.INSTANCE.allocationSize(index)
            + FfiConverterOptionalLong.INSTANCE.allocationSize(coinType)
            + FfiConverterOptionalLong.INSTANCE.allocationSize(change)
            + FfiConverterOptionalString.INSTANCE.allocationSize(path)
            + FfiConverterOptionalLong.INSTANCE.allocationSize(ss58Prefix)
            + FfiConverterString.INSTANCE.allocationSize(address));
          case AccountRow.Key(var id, var name, var kind, var keyData, var credentialId, var handle, var ua) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(id)
            + FfiConverterString.INSTANCE.allocationSize(name)
            + FfiConverterLong.INSTANCE.allocationSize(kind)
            + FfiConverterString.INSTANCE.allocationSize(keyData)
            + FfiConverterOptionalString.INSTANCE.allocationSize(credentialId)
            + FfiConverterOptionalString.INSTANCE.allocationSize(handle)
            + FfiConverterString.INSTANCE.allocationSize(ua));
          case AccountRow.Watch(var id, var name, var watch) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(id)
            + FfiConverterString.INSTANCE.allocationSize(name)
            + FfiConverterString.INSTANCE.allocationSize(watch));
        };
    }

    @Override
    public void write(AccountRow value, java.nio.ByteBuffer buf) {
      switch (value) {
        case AccountRow.Ua(var id, var name, var kind, var account, var index, var ua) -> {
          buf.putInt(1);
          FfiConverterString.INSTANCE.write(id, buf);
          FfiConverterString.INSTANCE.write(name, buf);
          FfiConverterLong.INSTANCE.write(kind, buf);
          FfiConverterLong.INSTANCE.write(account, buf);
          FfiConverterLong.INSTANCE.write(index, buf);
          FfiConverterString.INSTANCE.write(ua, buf);
        }
        case AccountRow.Native(var id, var name, var network, var index, var coinType, var change, var path, var ss58Prefix, var address) -> {
          buf.putInt(2);
          FfiConverterString.INSTANCE.write(id, buf);
          FfiConverterString.INSTANCE.write(name, buf);
          FfiConverterString.INSTANCE.write(network, buf);
          FfiConverterLong.INSTANCE.write(index, buf);
          FfiConverterOptionalLong.INSTANCE.write(coinType, buf);
          FfiConverterOptionalLong.INSTANCE.write(change, buf);
          FfiConverterOptionalString.INSTANCE.write(path, buf);
          FfiConverterOptionalLong.INSTANCE.write(ss58Prefix, buf);
          FfiConverterString.INSTANCE.write(address, buf);
        }
        case AccountRow.Key(var id, var name, var kind, var keyData, var credentialId, var handle, var ua) -> {
          buf.putInt(3);
          FfiConverterString.INSTANCE.write(id, buf);
          FfiConverterString.INSTANCE.write(name, buf);
          FfiConverterLong.INSTANCE.write(kind, buf);
          FfiConverterString.INSTANCE.write(keyData, buf);
          FfiConverterOptionalString.INSTANCE.write(credentialId, buf);
          FfiConverterOptionalString.INSTANCE.write(handle, buf);
          FfiConverterString.INSTANCE.write(ua, buf);
        }
        case AccountRow.Watch(var id, var name, var watch) -> {
          buf.putInt(4);
          FfiConverterString.INSTANCE.write(id, buf);
          FfiConverterString.INSTANCE.write(name, buf);
          FfiConverterString.INSTANCE.write(watch, buf);
        }
      };
    }
}




