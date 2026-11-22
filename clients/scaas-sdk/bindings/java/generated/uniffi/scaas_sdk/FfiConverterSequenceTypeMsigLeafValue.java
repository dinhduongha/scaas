package uniffi.scaas_sdk;


public enum FfiConverterSequenceTypeMsigLeafValue implements FfiConverterRustBuffer<java.util.List<MsigLeafValue>> {
  INSTANCE;

  @Override
  public java.util.List<MsigLeafValue> read(java.nio.ByteBuffer buf) {
    int len = buf.getInt();
    return java.util.stream.IntStream.range(0, len).mapToObj(_i -> FfiConverterTypeMsigLeafValue.INSTANCE.read(buf)).toList();
  }

  @Override
  public long allocationSize(java.util.List<MsigLeafValue> value) {
    long sizeForLength = 4L;
    long sizeForItems = value.stream().mapToLong(inner -> FfiConverterTypeMsigLeafValue.INSTANCE.allocationSize(inner)).sum();
    return sizeForLength + sizeForItems;
  }

  @Override
  public void write(java.util.List<MsigLeafValue> value, java.nio.ByteBuffer buf) {
    buf.putInt(value.size());
    value.forEach(inner -> FfiConverterTypeMsigLeafValue.INSTANCE.write(inner, buf));
  }
}



/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
