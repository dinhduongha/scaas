package uniffi.scaas_sdk;


public enum FfiConverterInt32Array implements FfiConverterRustBuffer<int[]> {
    INSTANCE;

    @Override
    public int[] read(java.nio.ByteBuffer buf) {
        int len = buf.getInt();
        int[] arr = new int[len];
        buf.asIntBuffer().get(arr);
        buf.position(buf.position() + len * 4);
        return arr;
    }

    @Override
    public long allocationSize(int[] value) {
        return 4L + (long) value.length * 4L;
    }

    @Override
    public void write(int[] value, java.nio.ByteBuffer buf) {
        buf.putInt(value.length);
        buf.asIntBuffer().put(value);
        buf.position(buf.position() + value.length * 4);
    }
}



/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
