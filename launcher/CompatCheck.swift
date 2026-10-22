// CompatCheck.swift -- two install-time helpers for the launcher:
//
//  * CompatCheck: reads a package's ABIs with the pure-Swift reader in
//    QuickLook/ApkInfo.swift and warns before installing an app that cannot run.
//  * UrlInstall: "Install from URL..." -- download an http(s) file with progress
//    and cancel, validate it is an APK or a split bundle, hand it to the
//    launcher's normal install funnel.
import AppKit
import Foundation

enum CompatCheck {
    struct Result {
        /// File names whose only native code is x86 (or non-ARM): cannot run.
        var x86Only: [String] = []
        /// One-line notes for the confirm dialog (32-bit only).
        var notes: [String] = []
    }

    /// Blocking (zip parse + decompress); call off the main thread.
    static func run(_ files: [URL]) -> Result {
        var r = Result()
        var only32: [String] = []
        for f in files {
            guard let info = loadApkInfo(url: f) else { continue }
            switch info.verdict {
            case .ok: break
            case .ok32: only32.append(f.lastPathComponent)
            case .no: r.x86Only.append(f.lastPathComponent)
            }
        }
        if files.count == 1, only32.count == 1 {
            r.notes.append(L("Note: this app only has 32-bit code. It runs, but is recompiled on first launch."))
        } else if !only32.isEmpty {
            r.notes.append(L("Note: %d of these apps only have 32-bit code. They run, but are recompiled on first launch.", only32.count))
        }
        return r
    }

    /// Modal warning. Returns true if the user installs anyway.
    static func confirmX86Only(_ names: [String]) -> Bool {
        if ProcessInfo.processInfo.environment["MACAPK_INSTALL_NOUI"] == "1" { return true }
        let alert = NSAlert()
        alert.alertStyle = .warning
        if names.count == 1 {
            alert.messageText = L("This app won't run on this Mac")
            alert.informativeText = L("%@ contains only x86 code and won't run on Apple Silicon. Install anyway?", names[0])
        } else {
            alert.messageText = L("Some apps won't run on this Mac")
            alert.informativeText = L("%d of these apps contain only x86 code and won't run on Apple Silicon:\n\n%@\n\nInstall anyway?",
                                      names.count, names.prefix(8).map { "  • " + $0 }.joined(separator: "\n"))
        }
        alert.addButton(withTitle: L("Cancel"))
        alert.addButton(withTitle: L("Install Anyway"))
        return alert.runModal() == .alertSecondButtonReturn
    }
}

/// Downloads one file with progress + cancel.
final class UrlInstall: NSObject, URLSessionDownloadDelegate {
    private var session: URLSession!
    private var task: URLSessionDownloadTask?
    private var panel: NSPanel?
    private var bar: NSProgressIndicator?
    private var label: NSTextField?
    private var onDone: ((Swift.Result<URL, UrlInstallError>) -> Void)?
    private var finished = false
    private static var active: UrlInstall?   // keeps self alive during the download

    struct UrlInstallError: Error { let message: String }

    /// Where downloads live. Persistent (not a temp dir) because the install
    /// records the source file's path and "Reset app" re-unpacks from it.
    static var downloadsDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Apk on Mac/Downloads", isDirectory: true)
    }

    /// Ask for a URL (prefilled from `initial` or the clipboard), download and validate.
    /// `autoStart` skips the prompt (used when a URL was dropped on the window).
    static func start(initial: String?, autoStart: Bool,
                      completion: @escaping (Swift.Result<URL, UrlInstallError>) -> Void) {
        var text = initial ?? ""
        if !autoStart {
            if text.isEmpty, let clip = NSPasteboard.general.string(forType: .string)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               let u = URL(string: clip), ["http", "https"].contains(u.scheme?.lowercased() ?? "") {
                text = clip
            }
            let alert = NSAlert()
            alert.messageText = L("Install from URL")
            alert.informativeText = L("Enter the web address of an .apk, .apkm, .xapk, .apks or .apkx file (http or https).")
            let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 360, height: 24))
            field.placeholderString = "https://example.com/app.apk"
            field.stringValue = text
            alert.accessoryView = field
            alert.addButton(withTitle: L("Download and Install"))
            alert.addButton(withTitle: L("Cancel"))
            alert.window.initialFirstResponder = field
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            text = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard let url = URL(string: text), let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https", url.host?.isEmpty == false else {
            completion(.failure(UrlInstallError(message: L("That is not a valid http or https address."))))
            return
        }
        let job = UrlInstall()
        active = job
        job.begin(url: url) { result in
            active = nil
            completion(result)
        }
    }

    private func begin(url: URL, done: @escaping (Swift.Result<URL, UrlInstallError>) -> Void) {
        onDone = done
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 30
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: .main)
        showPanel(host: url.host ?? url.absoluteString)
        task = session.downloadTask(with: url)
        task?.resume()
    }

    private func showPanel(host: String) {
        let p = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 380, height: 110),
                        styleMask: [.titled], backing: .buffered, defer: false)
        p.title = L("Downloading")
        let lbl = NSTextField(labelWithString: L("Downloading from %@…", host))
        lbl.frame = NSRect(x: 20, y: 70, width: 340, height: 20)
        lbl.lineBreakMode = .byTruncatingMiddle
        let b = NSProgressIndicator(frame: NSRect(x: 20, y: 46, width: 340, height: 14))
        b.isIndeterminate = true
        b.style = .bar
        b.startAnimation(nil)
        let cancel = NSButton(title: L("Cancel"), target: self, action: #selector(cancelTapped))
        cancel.frame = NSRect(x: 280, y: 8, width: 80, height: 28)
        cancel.keyEquivalent = "\u{1b}"
        for v in [lbl, b, cancel] as [NSView] { p.contentView?.addSubview(v) }
        p.center()
        p.makeKeyAndOrderFront(nil)
        panel = p; bar = b; label = lbl
    }

    @objc private func cancelTapped() {
        task?.cancel()
        finish(.failure(UrlInstallError(message: "")))   // empty message = silent
    }

    private func finish(_ r: Swift.Result<URL, UrlInstallError>) {
        guard !finished else { return }
        finished = true
        panel?.orderOut(nil)
        session.invalidateAndCancel()
        onDone?(r)
    }

    // MARK: URLSessionDownloadDelegate

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64, totalBytesWritten: Int64,
                    totalBytesExpectedToWrite: Int64) {
        let done = ByteCountFormatter.string(fromByteCount: totalBytesWritten, countStyle: .file)
        if totalBytesExpectedToWrite > 0 {
            bar?.isIndeterminate = false
            bar?.doubleValue = Double(totalBytesWritten) / Double(totalBytesExpectedToWrite) * 100
            let total = ByteCountFormatter.string(fromByteCount: totalBytesExpectedToWrite, countStyle: .file)
            label?.stringValue = L("Downloaded %@ of %@", done, total)
        } else {
            label?.stringValue = L("Downloaded %@", done)
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {
        if let http = downloadTask.response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            finish(.failure(UrlInstallError(message: L("The server answered with HTTP %d.", http.statusCode))))
            return
        }
        let fm = FileManager.default
        // Validate before keeping: must be a zip holding an APK manifest or inner APKs.
        guard let zip = ZipArchive(url: location),
              zip.entries["AndroidManifest.xml"] != nil
                || zip.order.contains(where: { $0.name.lowercased().hasSuffix(".apk") }) else {
            finish(.failure(UrlInstallError(message: L("That file is not an Android app package (no AndroidManifest.xml and no APK inside)."))))
            return
        }
        let isSplit = zip.entries["AndroidManifest.xml"] == nil
        var name = downloadTask.response?.suggestedFilename
            ?? downloadTask.originalRequest?.url?.lastPathComponent ?? "download"
        name = (name as NSString).lastPathComponent
        if name.isEmpty || name == "/" { name = "download" }
        if !kSupportedApkExtensions.contains((name as NSString).pathExtension.lowercased()) {
            name = (name as NSString).deletingPathExtension + (isSplit ? ".xapk" : ".apk")
        }
        let dir = Self.downloadsDir.appendingPathComponent(UUID().uuidString.prefix(8).lowercased(), isDirectory: true)
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
            let dest = dir.appendingPathComponent(name)
            try fm.moveItem(at: location, to: dest)
            finish(.success(dest))
        } catch {
            finish(.failure(UrlInstallError(message: error.localizedDescription)))
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let error = error, !finished else { return }
        if (error as NSError).code == NSURLErrorCancelled { return }
        finish(.failure(UrlInstallError(message: L("The download failed: %@", error.localizedDescription))))
    }
}
