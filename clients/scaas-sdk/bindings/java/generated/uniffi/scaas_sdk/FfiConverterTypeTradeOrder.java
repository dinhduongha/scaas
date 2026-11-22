package uniffi.scaas_sdk;


public enum FfiConverterTypeTradeOrder implements FfiConverterRustBuffer<TradeOrder> {
  INSTANCE;

  @Override
  public TradeOrder read(java.nio.ByteBuffer buf) {
    return new TradeOrder(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(TradeOrder value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.sellToken()) +
            FfiConverterString.INSTANCE.allocationSize(value.dex()) +
            FfiConverterString.INSTANCE.allocationSize(value.receiveToken()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterString.INSTANCE.allocationSize(value.receiveAmount()) +
            FfiConverterString.INSTANCE.allocationSize(value.minFill()) +
            FfiConverterString.INSTANCE.allocationSize(value.fee()) +
            FfiConverterString.INSTANCE.allocationSize(value.relayer()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.destination()) +
            FfiConverterByte.INSTANCE.allocationSize(value.flags()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.nonce()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntil())
      );
  }

  @Override
  public void write(TradeOrder value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.sellToken(), buf);
      FfiConverterString.INSTANCE.write(value.dex(), buf);
      FfiConverterString.INSTANCE.write(value.receiveToken(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterString.INSTANCE.write(value.receiveAmount(), buf);
      FfiConverterString.INSTANCE.write(value.minFill(), buf);
      FfiConverterString.INSTANCE.write(value.fee(), buf);
      FfiConverterString.INSTANCE.write(value.relayer(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.destination(), buf);
      FfiConverterByte.INSTANCE.write(value.flags(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.nonce(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntil(), buf);
  }
}



