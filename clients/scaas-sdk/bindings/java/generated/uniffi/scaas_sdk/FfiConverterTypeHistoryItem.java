package uniffi.scaas_sdk;


public enum FfiConverterTypeHistoryItem implements FfiConverterRustBuffer<HistoryItem> {
  INSTANCE;

  @Override
  public HistoryItem read(java.nio.ByteBuffer buf) {
    return new HistoryItem(
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(HistoryItem value) {
      return (
            FfiConverterLong.INSTANCE.allocationSize(value.block()) +
            FfiConverterString.INSTANCE.allocationSize(value.txHash()) +
            FfiConverterLong.INSTANCE.allocationSize(value.logIndex()) +
            FfiConverterString.INSTANCE.allocationSize(value.contract()) +
            FfiConverterString.INSTANCE.allocationSize(value.event()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.topics()) +
            FfiConverterString.INSTANCE.allocationSize(value.data())
      );
  }

  @Override
  public void write(HistoryItem value, java.nio.ByteBuffer buf) {
      FfiConverterLong.INSTANCE.write(value.block(), buf);
      FfiConverterString.INSTANCE.write(value.txHash(), buf);
      FfiConverterLong.INSTANCE.write(value.logIndex(), buf);
      FfiConverterString.INSTANCE.write(value.contract(), buf);
      FfiConverterString.INSTANCE.write(value.event(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.topics(), buf);
      FfiConverterString.INSTANCE.write(value.data(), buf);
  }
}



