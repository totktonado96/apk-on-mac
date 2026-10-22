import Foundation
import QuickLook
import Quartz
import UniformTypeIdentifiers

@objc(ApkPreviewProvider)
final class ApkPreviewProvider: QLPreviewProvider, QLPreviewingController {
    func providePreview(for request: QLFilePreviewRequest) async throws -> QLPreviewReply {
        guard let info = loadApkInfo(url: request.fileURL) else { throw CocoaError(.fileReadCorruptFile) }
        let reply = QLPreviewReply(dataOfContentType: .html, contentSize: CGSize(width: 560, height: 640)) { reply in
            if let icon = info.icon, let png = pngData(icon) {
                reply.attachments["icon.png"] = QLPreviewReplyAttachment(data: png, contentType: .png)
            }
            reply.stringEncoding = .utf8
            return Data(Self.html(info).utf8)
        }
        return reply
    }

    private static func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    }

    private static func html(_ i: ApkInfo) -> String {
        let size = ByteCountFormatter.string(fromByteCount: i.fileSize, countStyle: .file)
        let ver = i.versionName.isEmpty ? i.versionCode : (i.versionCode.isEmpty ? i.versionName : "\(i.versionName) (\(i.versionCode))")
        var rows: [(String, String)] = [("Package", i.package), ("Version", ver)]
        if !i.minSdk.isEmpty || !i.targetSdk.isEmpty {
            rows.append(("SDK", "min \(i.minSdk.isEmpty ? "?" : i.minSdk), target \(i.targetSdk.isEmpty ? "?" : i.targetSdk)"))
        }
        rows.append(("Size", size))
        rows.append(("Native ABIs", i.abis.isEmpty ? "none (pure Java/Kotlin)" : i.abis.joined(separator: ", ")))
        let top = 12
        var perms = i.permissions.prefix(top).map { "<code>\(esc($0))</code>" }.joined(separator: " ")
        if i.permissions.count > top { perms += " <span class=m>+\(i.permissions.count - top) more</span>" }
        if i.permissions.isEmpty { perms = "<span class=m>none</span>" }
        let cls: String
        switch i.verdict { case .ok: cls = "ok"; case .ok32: cls = "warn"; case .no: cls = "bad" }
        let iconTag = i.icon != nil ? "<img class=icon src=\"cid:icon.png\">" : "<div class=icon></div>"
        let rowHTML = rows.map { "<tr><th>\(esc($0.0))</th><td>\(esc($0.1))</td></tr>" }.joined()
        return """
        <!doctype html><html><head><meta charset="utf-8"><style>
        :root{color-scheme:light dark;--bg:#fff;--fg:#1d1d1f;--mu:#6e6e73;--card:#f5f5f7;--ok:#1d7a36;--okb:#e1f4e6;--wa:#8a5a00;--wab:#fff1d0;--ba:#b3261e;--bab:#fde4e2}
        @media(prefers-color-scheme:dark){:root{--bg:#1e1e1e;--fg:#f5f5f7;--mu:#98989d;--card:#2c2c2e;--ok:#5fd37d;--okb:#17301f;--wa:#ffc857;--wab:#3a2e10;--ba:#ff8a80;--bab:#3d1a18}}
        body{margin:0;padding:28px;background:var(--bg);color:var(--fg);font:14px -apple-system,BlinkMacSystemFont,sans-serif}
        .head{display:flex;gap:18px;align-items:center;margin-bottom:20px}
        .icon{width:88px;height:88px;border-radius:20px;background:var(--card);object-fit:contain;flex:none}
        h1{font-size:24px;margin:0 0 8px}
        .badge{display:inline-block;padding:4px 12px;border-radius:99px;font-weight:600;font-size:13px}
        .ok{background:var(--okb);color:var(--ok)}.warn{background:var(--wab);color:var(--wa)}.bad{background:var(--bab);color:var(--ba)}
        table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden}
        th,td{text-align:left;padding:9px 14px;vertical-align:top}th{color:var(--mu);font-weight:500;width:110px;white-space:nowrap}
        tr+tr{border-top:1px solid rgba(128,128,128,.18)}
        h2{font-size:13px;color:var(--mu);font-weight:600;margin:22px 0 8px;text-transform:uppercase;letter-spacing:.04em}
        code{display:inline-block;background:var(--card);padding:2px 8px;border-radius:6px;margin:2px 2px;font-size:12px}.m{color:var(--mu)}
        </style></head><body>
        <div class="head">\(iconTag)<div><h1>\(esc(i.label))</h1><span class="badge \(cls)">\(esc(i.verdictText))</span></div></div>
        <table>\(rowHTML)</table>
        <h2>Permissions</h2><div>\(perms)</div>
        </body></html>
        """
    }
}
