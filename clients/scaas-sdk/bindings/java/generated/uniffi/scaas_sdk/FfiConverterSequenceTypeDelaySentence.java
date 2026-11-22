package uniffi.scaas_sdk;


public enum FfiConverterSequenceTypeDelaySentence implements FfiConverterRustBuffer<java.util.List<DelaySentence>> {
  INSTANCE;

  @Override
  public java.util.List<DelaySentence> read(java.nio.ByteBuffer buf) {
    int len = buf.getInt();
    return java.util.stream.IntStream.range(0, len).mapToObj(_i -> FfiConverterTypeDelaySentence.INSTANCE.read(buf)).toList();
  }

  @Override
  public long allocationSize(java.util.List<DelaySentence> value) {
    long sizeForLength = 4L;
    long sizeForItems = value.stream().mapToLong(inner -> FfiConverterTypeDelaySentence.INSTANCE.allocationSize(inner)).sum();
    return sizeForLength + sizeForItems;
  }

  @Override
  public void write(java.util.List<DelaySentence> value, java.nio.ByteBuffer buf) {
    buf.putInt(value.size());
    value.forEach(inner -> FfiConverterTypeDelaySentence.INSTANCE.write(inner, buf));
  }
}



/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
