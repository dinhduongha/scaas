package uniffi.scaas_sdk;


public enum FfiConverterSequenceTypeGasBase implements FfiConverterRustBuffer<java.util.List<GasBase>> {
  INSTANCE;

  @Override
  public java.util.List<GasBase> read(java.nio.ByteBuffer buf) {
    int len = buf.getInt();
    return java.util.stream.IntStream.range(0, len).mapToObj(_i -> FfiConverterTypeGasBase.INSTANCE.read(buf)).toList();
  }

  @Override
  public long allocationSize(java.util.List<GasBase> value) {
    long sizeForLength = 4L;
    long sizeForItems = value.stream().mapToLong(inner -> FfiConverterTypeGasBase.INSTANCE.allocationSize(inner)).sum();
    return sizeForLength + sizeForItems;
  }

  @Override
  public void write(java.util.List<GasBase> value, java.nio.ByteBuffer buf) {
    buf.putInt(value.size());
    value.forEach(inner -> FfiConverterTypeGasBase.INSTANCE.write(inner, buf));
  }
}



/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
