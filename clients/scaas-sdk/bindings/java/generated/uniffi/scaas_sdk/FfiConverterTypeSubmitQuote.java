package uniffi.scaas_sdk;


public enum FfiConverterTypeSubmitQuote implements FfiConverterRustBuffer<SubmitQuote> {
  INSTANCE;

  @Override
  public SubmitQuote read(java.nio.ByteBuffer buf) {
    return new SubmitQuote(
      FfiConverterTypeSubmitPath.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterOptionalTypeGasSources.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInt32Array.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SubmitQuote value) {
      return (
            FfiConverterTypeSubmitPath.INSTANCE.allocationSize(value.path()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.payer()) +
            FfiConverterLong.INSTANCE.allocationSize(value.gasLimit()) +
            FfiConverterLong.INSTANCE.allocationSize(value.regularGas()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.gas()) +
            FfiConverterOptionalTypeGasSources.INSTANCE.allocationSize(value.gasFrom()) +
            FfiConverterString.INSTANCE.allocationSize(value.maxFeePerGas()) +
            FfiConverterString.INSTANCE.allocationSize(value.maxPriorityFeePerGas()) +
            FfiConverterString.INSTANCE.allocationSize(value.maxCost()) +
            FfiConverterString.INSTANCE.allocationSize(value.feeToRelayer()) +
            FfiConverterInt32Array.INSTANCE.allocationSize(value.gateways()) +
            FfiConverterLong.INSTANCE.allocationSize(value.txNonce()) +
            FfiConverterByte.INSTANCE.allocationSize(value.txType())
      );
  }

  @Override
  public void write(SubmitQuote value, java.nio.ByteBuffer buf) {
      FfiConverterTypeSubmitPath.INSTANCE.write(value.path(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.payer(), buf);
      FfiConverterLong.INSTANCE.write(value.gasLimit(), buf);
      FfiConverterLong.INSTANCE.write(value.regularGas(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.gas(), buf);
      FfiConverterOptionalTypeGasSources.INSTANCE.write(value.gasFrom(), buf);
      FfiConverterString.INSTANCE.write(value.maxFeePerGas(), buf);
      FfiConverterString.INSTANCE.write(value.maxPriorityFeePerGas(), buf);
      FfiConverterString.INSTANCE.write(value.maxCost(), buf);
      FfiConverterString.INSTANCE.write(value.feeToRelayer(), buf);
      FfiConverterInt32Array.INSTANCE.write(value.gateways(), buf);
      FfiConverterLong.INSTANCE.write(value.txNonce(), buf);
      FfiConverterByte.INSTANCE.write(value.txType(), buf);
  }
}



