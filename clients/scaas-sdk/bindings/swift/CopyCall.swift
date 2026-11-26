// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk spec §5, §16.1: the reference library's secret copy calls for Swift (plan T20f; review B12), found in the loaded
// library by name. A secret's bytes cross only here, never through the generated codec: write copies a buffer into the
// secret named by its id and zeroes the buffer, read copies a secret out (the caller zeroes what it read once done), dispose
// zeroes and frees a secret. A Swift String cannot be zeroed: pass [UInt8].
import Foundation

#if canImport(Glibc)
    import Glibc
#endif

public enum CopyCall {
    private typealias Write = @convention(c) (UInt64, UnsafePointer<UInt8>?, Int) -> Int32
    private typealias Read = @convention(c) (UInt64, UnsafeMutablePointer<UInt8>?, Int) -> Int64
    private typealias Dispose = @convention(c) (UInt64) -> Int32
    private static let handle = dlopen(nil, RTLD_NOW)
    private static let writeC = unsafeBitCast(dlsym(handle, "scaas_sdk_secret_write"), to: Write.self)
    private static let readC = unsafeBitCast(dlsym(handle, "scaas_sdk_secret_read"), to: Read.self)
    private static let disposeC = unsafeBitCast(dlsym(handle, "scaas_sdk_secret_dispose"), to: Dispose.self)

    /// `buf` into secret `id` (its length exactly), then `buf` zeroed (also on a refusal); false on a refusal.
    public static func write(_ id: UInt64, _ buf: inout [UInt8]) -> Bool {
        let r = buf.withUnsafeBufferPointer { writeC(id, $0.baseAddress, $0.count) }
        buf.withUnsafeMutableBytes { if let p = $0.baseAddress { _ = memset(p, 0, $0.count) } }
        return r == 0
    }

    /// Secret `id` (at most `cap` bytes) out; nil when refused.
    public static func read(_ id: UInt64, cap: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: cap)
        return read(id, via: &out)
    }

    /// `read` through the buffer `out` (its count the cap): the secret's bytes are copied out of it, then it is zeroed, so no
    /// copy stays behind but the one returned (review T26 C-5).
    public static func read(_ id: UInt64, via out: inout [UInt8]) -> [UInt8]? {
        let n = out.withUnsafeMutableBufferPointer { readC(id, $0.baseAddress, $0.count) }
        let r = n < 0 ? nil : Array(out[0..<Int(n)])
        out.withUnsafeMutableBytes { if let p = $0.baseAddress { _ = memset(p, 0, $0.count) } }
        return r
    }

    /// Secret `id` zeroed and freed; false when unknown.
    public static func dispose(_ id: UInt64) -> Bool { disposeC(id) == 0 }
}
