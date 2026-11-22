package uniffi.scaas_sdk;


public enum FfiConverterTypeLimits implements FfiConverterRustBuffer<Limits> {
  INSTANCE;

  @Override
  public Limits read(java.nio.ByteBuffer buf) {
    return new Limits(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterSequenceTypeNativeCap.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Limits value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.maxFeePerGas()) +
            FfiConverterLong.INSTANCE.allocationSize(value.maxGas()) +
            FfiConverterString.INSTANCE.allocationSize(value.maxCost()) +
            FfiConverterLong.INSTANCE.allocationSize(value.watchPollMs()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.maxWatch()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.maxConcurrentHeavy()) +
            FfiConverterLong.INSTANCE.allocationSize(value.maxValidSecs()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.eventQueue()) +
            FfiConverterLong.INSTANCE.allocationSize(value.stateRetentionSecs()) +
            FfiConverterSequenceTypeNativeCap.INSTANCE.allocationSize(value.maxNativeCost())
      );
  }

  @Override
  public void write(Limits value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.maxFeePerGas(), buf);
      FfiConverterLong.INSTANCE.write(value.maxGas(), buf);
      FfiConverterString.INSTANCE.write(value.maxCost(), buf);
      FfiConverterLong.INSTANCE.write(value.watchPollMs(), buf);
      FfiConverterInteger.INSTANCE.write(value.maxWatch(), buf);
      FfiConverterInteger.INSTANCE.write(value.maxConcurrentHeavy(), buf);
      FfiConverterLong.INSTANCE.write(value.maxValidSecs(), buf);
      FfiConverterInteger.INSTANCE.write(value.eventQueue(), buf);
      FfiConverterLong.INSTANCE.write(value.stateRetentionSecs(), buf);
      FfiConverterSequenceTypeNativeCap.INSTANCE.write(value.maxNativeCost(), buf);
  }
}



