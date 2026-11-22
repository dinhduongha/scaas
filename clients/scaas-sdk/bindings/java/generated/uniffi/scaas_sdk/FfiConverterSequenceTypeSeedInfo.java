package uniffi.scaas_sdk;


public enum FfiConverterSequenceTypeSeedInfo implements FfiConverterRustBuffer<java.util.List<SeedInfo>> {
  INSTANCE;

  @Override
  public java.util.List<SeedInfo> read(java.nio.ByteBuffer buf) {
    int len = buf.getInt();
    return java.util.stream.IntStream.range(0, len).mapToObj(_i -> FfiConverterTypeSeedInfo.INSTANCE.read(buf)).toList();
  }

  @Override
  public long allocationSize(java.util.List<SeedInfo> value) {
    long sizeForLength = 4L;
    long sizeForItems = value.stream().mapToLong(inner -> FfiConverterTypeSeedInfo.INSTANCE.allocationSize(inner)).sum();
    return sizeForLength + sizeForItems;
  }

  @Override
  public void write(java.util.List<SeedInfo> value, java.nio.ByteBuffer buf) {
    buf.putInt(value.size());
    value.forEach(inner -> FfiConverterTypeSeedInfo.INSTANCE.write(inner, buf));
  }
}



/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
