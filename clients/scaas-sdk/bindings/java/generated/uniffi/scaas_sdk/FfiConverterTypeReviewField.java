package uniffi.scaas_sdk;


public enum FfiConverterTypeReviewField implements FfiConverterRustBuffer<ReviewField> {
  INSTANCE;

  @Override
  public ReviewField read(java.nio.ByteBuffer buf) {
    return new ReviewField(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeSource.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ReviewField value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.name()) +
            FfiConverterString.INSTANCE.allocationSize(value.value()) +
            FfiConverterString.INSTANCE.allocationSize(value.display()) +
            FfiConverterTypeSource.INSTANCE.allocationSize(value.source())
      );
  }

  @Override
  public void write(ReviewField value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.name(), buf);
      FfiConverterString.INSTANCE.write(value.value(), buf);
      FfiConverterString.INSTANCE.write(value.display(), buf);
      FfiConverterTypeSource.INSTANCE.write(value.source(), buf);
  }
}



