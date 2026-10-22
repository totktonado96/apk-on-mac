// ApkInfo.swift -- tiny pure-Swift APK reader for the Quick Look extensions.
// Zip central directory + raw deflate (Compression), binary AndroidManifest
// (AXML), resources.arsc lookup, and adaptive-icon composition. No runtime,
// no subprocess: the extensions are sandboxed.
import Foundation
import Compression
import CoreGraphics
import ImageIO

// MARK: - byte helpers

struct Bytes {
    let b: [UInt8]
    init(_ d: Data) { b = [UInt8](d) }
    func u8(_ o: Int) -> Int { o >= 0 && o < b.count ? Int(b[o]) : 0 }
    func u16(_ o: Int) -> Int { o >= 0 && o + 1 < b.count ? Int(b[o]) | Int(b[o + 1]) << 8 : 0 }
    func u32(_ o: Int) -> Int {
        guard o >= 0, o + 3 < b.count else { return 0 }
        return Int(b[o]) | Int(b[o + 1]) << 8 | Int(b[o + 2]) << 16 | Int(b[o + 3]) << 24
    }
}

// MARK: - zip

struct ZipEntry { let name: String; let method: Int; let csize: Int; let usize: Int; let lho: Int }

final class ZipArchive {
    let data: Data
    private(set) var entries: [String: ZipEntry] = [:]
    private(set) var order: [ZipEntry] = []

    init?(url: URL) {
        guard let d = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        self.data = d
        guard parse() else { return nil }
    }
    init?(data: Data) {
        self.data = data
        guard parse() else { return nil }
    }

    private func r16(_ o: Int) -> Int { Int(data[o]) | Int(data[o + 1]) << 8 }
    private func r32(_ o: Int) -> Int { r16(o) | r16(o + 2) << 16 }

    private func parse() -> Bool {
        let n = data.count
        guard n > 22 else { return false }
        var p = n - 22
        let lowest = max(0, n - 22 - 65535)
        while p >= lowest {
            if r32(p) == 0x06054b50 { break }
            p -= 1
        }
        guard p >= lowest else { return false }
        let count = r16(p + 10)
        var o = r32(p + 16)
        for _ in 0..<count {
            guard o + 46 <= n, r32(o) == 0x02014b50 else { break }
            let nl = r16(o + 28), el = r16(o + 30), cl = r16(o + 32)
            guard o + 46 + nl <= n else { break }
            let name = String(decoding: data[(o + 46)..<(o + 46 + nl)], as: UTF8.self)
            let e = ZipEntry(name: name, method: r16(o + 10), csize: r32(o + 20), usize: r32(o + 24), lho: r32(o + 42))
            entries[name] = e
            order.append(e)
            o += 46 + nl + el + cl
        }
        return !entries.isEmpty
    }

    func read(_ name: String) -> Data? {
        guard let e = entries[name] else { return nil }
        let h = e.lho
        guard h + 30 <= data.count, r32(h) == 0x04034b50 else { return nil }
        let start = h + 30 + r16(h + 26) + r16(h + 28)
        guard start + e.csize <= data.count else { return nil }
        let raw = data.subdata(in: start..<(start + e.csize))
        if e.method == 0 { return raw }
        guard e.method == 8, e.usize > 0, e.usize < 512 * 1024 * 1024 else { return nil }
        var out = Data(count: e.usize)
        let got: Int = out.withUnsafeMutableBytes { dst in
            raw.withUnsafeBytes { src in
                compression_decode_buffer(dst.bindMemory(to: UInt8.self).baseAddress!, e.usize,
                                          src.bindMemory(to: UInt8.self).baseAddress!, e.csize,
                                          nil, COMPRESSION_ZLIB)
            }
        }
        return got == e.usize ? out : nil
    }
}

// MARK: - AXML

struct StringPool {
    var strings: [String] = []
    init() {}
    init(_ x: Bytes, at c: Int) {
        let count = x.u32(c + 8), flags = x.u32(c + 16), sStart = x.u32(c + 20)
        let utf8 = flags & (1 << 8) != 0
        strings.reserveCapacity(count)
        for i in 0..<count {
            var p = c + sStart + x.u32(c + 28 + i * 4)
            if utf8 {
                var l = x.u8(p); p += 1
                if l & 0x80 != 0 { p += 1 }
                l = x.u8(p); p += 1
                if l & 0x80 != 0 { l = (l & 0x7f) << 8 | x.u8(p); p += 1 }
                guard p >= 0, p + l <= x.b.count else { strings.append(""); continue }
                strings.append(String(decoding: x.b[p..<(p + l)], as: UTF8.self))
            } else {
                var l = x.u16(p); p += 2
                if l & 0x8000 != 0 { l = (l & 0x7fff) << 16 | x.u16(p); p += 2 }
                guard p >= 0, p + l * 2 <= x.b.count else { strings.append(""); continue }
                var u = [UInt16](); u.reserveCapacity(l)
                for k in 0..<l { u.append(UInt16(x.u16(p + k * 2))) }
                strings.append(String(decoding: u, as: UTF16.self))
            }
        }
    }
    subscript(i: Int) -> String { i >= 0 && i < strings.count ? strings[i] : "" }
}

struct AXAttr { let name: String; let type: Int; let data: Int; let raw: String? }
struct AXElement { let name: String; let attrs: [AXAttr]
    func attr(_ n: String) -> AXAttr? { attrs.first { $0.name == n } } }

func parseAXML(_ d: Data) -> [AXElement] {
    let x = Bytes(d)
    guard x.u16(0) == 0x0003 else { return [] }
    var pool = StringPool()
    var resMap: [Int] = []
    var out: [AXElement] = []
    var o = x.u16(2)
    let known: [Int: String] = [0x01010001: "label", 0x01010002: "icon", 0x01010003: "name",
                                0x0101020c: "minSdkVersion", 0x01010270: "targetSdkVersion",
                                0x0101021b: "versionCode", 0x0101021c: "versionName",
                                0x01010199: "drawable"]
    while o + 8 <= x.b.count {
        let type = x.u16(o), size = x.u32(o + 4)
        if size < 8 { break }
        switch type {
        case 0x0001: pool = StringPool(x, at: o)
        case 0x0180:
            let n = (size - 8) / 4
            resMap = (0..<n).map { x.u32(o + 8 + $0 * 4) }
        case 0x0102:
            let ext = o + 16
            let name = pool[x.u32(ext + 4)]
            let aStart = x.u16(ext + 8), aSize = x.u16(ext + 10), aCount = x.u16(ext + 12)
            var attrs: [AXAttr] = []
            for i in 0..<aCount {
                let a = ext + aStart + i * max(aSize, 20)
                let ni = x.u32(a + 4)
                var an = pool[ni]
                if ni >= 0, ni < resMap.count, let k = known[resMap[ni]] { an = k }
                let ri = x.u32(a + 8)
                let raw: String? = (ri >= 0 && ri < pool.strings.count) ? pool[ri] : nil
                attrs.append(AXAttr(name: an, type: x.u8(a + 15), data: x.u32(a + 16), raw: raw))
            }
            out.append(AXElement(name: name, attrs: attrs))
        default: break
        }
        o += size
    }
    return out
}

// MARK: - resources.arsc

struct ResVal { let density: Int; let localeZero: Bool; let type: Int; let data: Int }

final class ResTable {
    let x: Bytes
    var global = StringPool()
    private var types: [Int: [Int]] = [:]   // (pkg<<8|type) -> chunk offsets

    init?(_ d: Data) {
        x = Bytes(d)
        guard x.u16(0) == 0x0002 else { return nil }
        var o = x.u16(2)
        while o + 8 <= x.b.count {
            let t = x.u16(o), s = x.u32(o + 4)
            if s < 8 { break }
            if t == 0x0001 && global.strings.isEmpty { global = StringPool(x, at: o) }
            else if t == 0x0200 {
                let pid = x.u32(o + 8)
                var p = o + x.u16(o + 2)
                let end = min(o + s, x.b.count)
                while p + 8 <= end {
                    let pt = x.u16(p), ps = x.u32(p + 4)
                    if ps < 8 { break }
                    if pt == 0x0201 { types[pid << 8 | x.u8(p + 8), default: []].append(p) }
                    p += ps
                }
            }
            o += s
        }
    }

    func lookup(_ id: Int) -> [ResVal] {
        let key = (id >> 24) << 8 | (id >> 16) & 0xff
        let entry = id & 0xffff
        var res: [ResVal] = []
        for c in types[key] ?? [] {
            let hs = x.u16(c + 2), flags = x.u8(c + 9), count = x.u32(c + 12), es = x.u32(c + 16)
            var off = -1
            if flags & 1 != 0 {
                for i in 0..<count where x.u16(c + hs + i * 4) == entry { off = x.u16(c + hs + i * 4 + 2) * 4 }
            } else if entry < count {
                if flags & 2 != 0 { let v = x.u16(c + hs + entry * 2); off = v == 0xffff ? -1 : v * 4 }
                else { let v = x.u32(c + hs + entry * 4); off = v == 0xffffffff || v < 0 ? -1 : v }
            }
            guard off >= 0 else { continue }
            let e = c + es + off
            if x.u16(e + 2) & 1 != 0 { continue }   // complex (bag)
            let vt = x.u8(e + 11)
            res.append(ResVal(density: x.u16(c + 34), localeZero: x.u32(c + 28) == 0, type: vt, data: x.u32(e + 12)))
        }
        return res
    }

    /// Best default-config value, following references.
    func best(_ id: Int, depth: Int = 0) -> ResVal? {
        let vals = lookup(id)
        let v = vals.first(where: { $0.localeZero && $0.density == 0 }) ?? vals.first(where: { $0.localeZero }) ?? vals.first
        if let v = v, v.type == 0x01, depth < 4, v.data != id { return best(v.data, depth: depth + 1) ?? v }
        return v
    }
    func string(_ id: Int) -> String? {
        guard let v = best(id), v.type == 0x03 else { return nil }
        return global[v.data]
    }
    /// All file-path candidates (string values) for a drawable/mipmap id.
    func files(_ id: Int, depth: Int = 0) -> [(density: Int, path: String)] {
        var r: [(Int, String)] = []
        for v in lookup(id) {
            if v.type == 0x03 { r.append((v.density, global[v.data])) }
            else if v.type == 0x01, depth < 4, v.data != id { r += files(v.data, depth: depth + 1) }
        }
        return r
    }
}

// MARK: - APK info

struct ApkInfo {
    var package = "", label = "", versionName = "", versionCode = ""
    var minSdk = "", targetSdk = ""
    var abis: [String] = []
    var permissions: [String] = []
    var fileSize: Int64 = 0
    var icon: CGImage?

    enum Verdict { case ok, ok32, no }
    var verdict: Verdict {
        if abis.isEmpty || abis.contains("arm64-v8a") { return .ok }
        if abis.contains("armeabi-v7a") || abis.contains("armeabi") { return .ok32 }
        return .no
    }
    var verdictText: String {
        switch verdict {
        case .ok: return "Runs on Apple Silicon"
        case .ok32: return "Runs (32-bit, recompiled)"
        case .no: return "Won't run: " + (abis.allSatisfy { $0.hasPrefix("x86") } ? "x86-only" : "no ARM libraries")
        }
    }
}

private func decodeImage(_ d: Data) -> CGImage? {
    guard let s = CGImageSourceCreateWithData(d as CFData, nil) else { return nil }
    return CGImageSourceCreateImageAtIndex(s, 0, nil)
}

private func isRaster(_ p: String) -> Bool {
    let l = p.lowercased(); return l.hasSuffix(".png") || l.hasSuffix(".webp") || l.hasSuffix(".jpg")
}

private func argb(_ v: Int) -> CGColor {
    CGColor(red: CGFloat(v >> 16 & 255) / 255, green: CGFloat(v >> 8 & 255) / 255,
            blue: CGFloat(v & 255) / 255, alpha: CGFloat(v >> 24 & 255) / 255)
}

/// Compose adaptive icon (background + foreground), crop to the 72/108 safe
/// zone and mask with a rounded square.
private func composeAdaptive(zip: ZipArchive, table: ResTable?, xmlPath: String) -> CGImage? {
    guard let xd = zip.read(xmlPath) else { return nil }
    let els = parseAXML(xd)
    func layer(_ n: String) -> (CGImage?, CGColor?) {
        guard let a = els.first(where: { $0.name == n })?.attr("drawable") else { return (nil, nil) }
        if a.type >= 0x1c && a.type <= 0x1f { return (nil, argb(a.data)) }
        guard a.type == 0x01, let t = table else { return (nil, nil) }
        if let v = t.best(a.data), v.type >= 0x1c && v.type <= 0x1f { return (nil, argb(v.data)) }
        let f = t.files(a.data).filter { isRaster($0.path) }.max { $0.density < $1.density }
        if let f = f, let d = zip.read(f.path) { return (decodeImage(d), nil) }
        return (nil, nil)
    }
    let (fg, _) = layer("foreground")
    guard let fgi = fg else { return nil }
    let (bgi, bgc) = layer("background")
    let S = 512, full = CGFloat(S) * 108 / 72
    guard let ctx = CGContext(data: nil, width: S, height: S, bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpace(name: CGColorSpace.sRGB)!,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
    let r = CGRect(x: 0, y: 0, width: S, height: S)
    ctx.addPath(CGPath(roundedRect: r, cornerWidth: CGFloat(S) * 0.225, cornerHeight: CGFloat(S) * 0.225, transform: nil))
    ctx.clip()
    let big = CGRect(x: (CGFloat(S) - full) / 2, y: (CGFloat(S) - full) / 2, width: full, height: full)
    ctx.setFillColor(bgc ?? CGColor(gray: 1, alpha: 1)); ctx.fill(r)
    if let b = bgi { ctx.draw(b, in: big) }
    ctx.draw(fgi, in: big)
    return ctx.makeImage()
}

func loadApkInfo(url: URL) -> ApkInfo? {
    guard let outer = ZipArchive(url: url) else { return nil }
    var info = ApkInfo()
    info.fileSize = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map { Int64($0) } ?? Int64(outer.data.count)
    var zip = outer
    var abiSet = Set<String>()
    if outer.entries["AndroidManifest.xml"] == nil {
        // split bundle (xapk/apkm/apks): find the base APK, note ABIs from split names
        let apks = outer.order.filter { $0.name.lowercased().hasSuffix(".apk") }
        for e in apks {
            let n = e.name.lowercased()
            for (key, abi) in [("arm64_v8a", "arm64-v8a"), ("armeabi_v7a", "armeabi-v7a"), ("x86_64", "x86_64"), ("x86", "x86")]
            where n.contains(key) { abiSet.insert(abi); break }
        }
        let base = apks.first { $0.name.lowercased().hasSuffix("base.apk") }
            ?? apks.filter { !$0.name.lowercased().contains("config.") && !$0.name.lowercased().contains("split_") }
                   .max { $0.usize < $1.usize }
            ?? apks.max { $0.usize < $1.usize }
        guard let b = base, let bd = outer.read(b.name), let inner = ZipArchive(data: bd) else { return nil }
        zip = inner
    }
    guard let mdata = zip.read("AndroidManifest.xml") else { return nil }
    let els = parseAXML(mdata)
    guard let man = els.first(where: { $0.name == "manifest" }) else { return nil }
    func s(_ a: AXAttr?) -> String {
        guard let a = a else { return "" }
        if a.type == 0x03 { return a.raw ?? "" }
        if a.type == 0x10 { return String(a.data) }
        return a.raw ?? ""
    }
    info.package = s(man.attr("package"))
    info.versionName = s(man.attr("versionName"))
    info.versionCode = s(man.attr("versionCode"))
    if let u = els.first(where: { $0.name == "uses-sdk" }) {
        info.minSdk = s(u.attr("minSdkVersion")); info.targetSdk = s(u.attr("targetSdkVersion"))
    }
    info.permissions = els.filter { $0.name == "uses-permission" }.compactMap { $0.attr("name")?.raw }
        .map { $0.hasPrefix("android.permission.") ? String($0.dropFirst(19)) : $0 }
    for e in zip.order where e.name.hasPrefix("lib/") {
        let parts = e.name.split(separator: "/")
        if parts.count >= 3 { abiSet.insert(String(parts[1])) }
    }
    info.abis = abiSet.sorted()
    let table = zip.read("resources.arsc").flatMap { ResTable($0) }
    let app = els.first { $0.name == "application" }
    if let l = app?.attr("label") {
        if l.type == 0x01, let t = table { info.label = t.string(l.data) ?? "" } else { info.label = s(l) }
    }
    if info.label.isEmpty { info.label = info.package }

    // icon
    var cands: [(density: Int, path: String)] = []
    if let ia = app?.attr("icon") {
        if ia.type == 0x01, let t = table { cands = t.files(ia.data) }
        else if ia.type == 0x03, let r = ia.raw { cands = [(0, r)] }
    }
    if let x = cands.filter({ $0.path.lowercased().hasSuffix(".xml") })
        .sorted(by: { $0.density > $1.density }).first {
        info.icon = composeAdaptive(zip: zip, table: table, xmlPath: x.path)
    }
    if info.icon == nil,
       let r = cands.filter({ isRaster($0.path) }).max(by: { ($0.density == 0xffff ? 0 : $0.density) < ($1.density == 0xffff ? 0 : $1.density) }),
       let d = zip.read(r.path) { info.icon = decodeImage(d) }
    if info.icon == nil {
        let guess = zip.order.filter { $0.name.hasPrefix("res/") && isRaster($0.name) && $0.name.contains("ic_launcher") && !$0.name.contains("foreground") && !$0.name.contains("background") }
            .max { $0.usize < $1.usize }
        if let g = guess, let d = zip.read(g.name) { info.icon = decodeImage(d) }
    }
    return info
}

func pngData(_ img: CGImage) -> Data? {
    let d = NSMutableData()
    guard let dst = CGImageDestinationCreateWithData(d, "public.png" as CFString, 1, nil) else { return nil }
    CGImageDestinationAddImage(dst, img, nil)
    return CGImageDestinationFinalize(dst) ? d as Data : nil
}
