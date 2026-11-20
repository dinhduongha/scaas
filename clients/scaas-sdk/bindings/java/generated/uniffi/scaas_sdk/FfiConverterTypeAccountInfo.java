package uniffi.scaas_sdk;


public enum FfiConverterTypeAccountInfo implements FfiConverterRustBuffer<AccountInfo> {
  INSTANCE;

  @Override
  public AccountInfo read(java.nio.ByteBuffer buf) {
    return new AccountInfo(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalShort.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AccountInfo value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.id()) +
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.name()) +
            FfiConverterString.INSTANCE.allocationSize(value.shape()) +
            FfiConverterOptionalShort.INSTANCE.allocationSize(value.kind()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.index()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.network()) +
            FfiConverterString.INSTANCE.allocationSize(value.idText()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.verified()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.delegated())
      );
  }

  @Override
  public void write(AccountInfo value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.id(), buf);
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
      FfiConverterString.INSTANCE.write(value.shape(), buf);
      FfiConverterOptionalShort.INSTANCE.write(value.kind(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.account(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.index(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.network(), buf);
      FfiConverterString.INSTANCE.write(value.idText(), buf);
      FfiConverterBoolean.INSTANCE.write(value.verified(), buf);
      FfiConverterBoolean.INSTANCE.write(value.delegated(), buf);
  }
}



