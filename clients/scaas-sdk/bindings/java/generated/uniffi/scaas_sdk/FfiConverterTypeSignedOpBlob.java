package uniffi.scaas_sdk;


public enum FfiConverterTypeSignedOpBlob implements FfiConverterRustBuffer<SignedOpBlob> {
  INSTANCE;

  @Override
  public SignedOpBlob read(java.nio.ByteBuffer buf) {
    return new SignedOpBlob(
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeValue.INSTANCE.read(buf),
      FfiConverterTypeValue.INSTANCE.read(buf),
      FfiConverterTypeValue.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SignedOpBlob value) {
      return (
            FfiConverterInteger.INSTANCE.allocationSize(value.v()) +
            FfiConverterString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterString.INSTANCE.allocationSize(value.family()) +
            FfiConverterString.INSTANCE.allocationSize(value.contract()) +
            FfiConverterString.INSTANCE.allocationSize(value.entry()) +
            FfiConverterString.INSTANCE.allocationSize(value.name()) +
            FfiConverterString.INSTANCE.allocationSize(value.kind()) +
            FfiConverterTypeValue.INSTANCE.allocationSize(value.message()) +
            FfiConverterTypeValue.INSTANCE.allocationSize(value.extra()) +
            FfiConverterTypeValue.INSTANCE.allocationSize(value.signature()) +
            FfiConverterString.INSTANCE.allocationSize(value.signer()) +
            FfiConverterShort.INSTANCE.allocationSize(value.signerKind()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.ids())
      );
  }

  @Override
  public void write(SignedOpBlob value, java.nio.ByteBuffer buf) {
      FfiConverterInteger.INSTANCE.write(value.v(), buf);
      FfiConverterString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterString.INSTANCE.write(value.family(), buf);
      FfiConverterString.INSTANCE.write(value.contract(), buf);
      FfiConverterString.INSTANCE.write(value.entry(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
      FfiConverterString.INSTANCE.write(value.kind(), buf);
      FfiConverterTypeValue.INSTANCE.write(value.message(), buf);
      FfiConverterTypeValue.INSTANCE.write(value.extra(), buf);
      FfiConverterTypeValue.INSTANCE.write(value.signature(), buf);
      FfiConverterString.INSTANCE.write(value.signer(), buf);
      FfiConverterShort.INSTANCE.write(value.signerKind(), buf);
      FfiConverterBoolean.INSTANCE.write(value.ids(), buf);
  }
}



