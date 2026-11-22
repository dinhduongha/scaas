package uniffi.scaas_sdk;


public enum FfiConverterSequenceTypeTokenBalance implements FfiConverterRustBuffer<java.util.List<TokenBalance>> {
  INSTANCE;

  @Override
  public java.util.List<TokenBalance> read(java.nio.ByteBuffer buf) {
    int len = buf.getInt();
    return java.util.stream.IntStream.range(0, len).mapToObj(_i -> FfiConverterTypeTokenBalance.INSTANCE.read(buf)).toList();
  }

  @Override
  public long allocationSize(java.util.List<TokenBalance> value) {
    long sizeForLength = 4L;
    long sizeForItems = value.stream().mapToLong(inner -> FfiConverterTypeTokenBalance.INSTANCE.allocationSize(inner)).sum();
    return sizeForLength + sizeForItems;
  }

  @Override
  public void write(java.util.List<TokenBalance> value, java.nio.ByteBuffer buf) {
    buf.putInt(value.size());
    value.forEach(inner -> FfiConverterTypeTokenBalance.INSTANCE.write(inner, buf));
  }
}



/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
