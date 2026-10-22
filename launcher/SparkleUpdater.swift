import Foundation

// Sparkle 2 auto-update. Compiled in only when scripts/build_launcher.sh finds
// Sparkle.framework (SPARKLE_DIR); otherwise the GitHub-API UpdateChecker in
// UpdateCheck.swift remains the fallback. Feed and EdDSA public key live in
// Info.plist (SUFeedURL, SUPublicEDKey).
#if canImport(Sparkle)
import Sparkle

@MainActor
enum AppUpdater {
    static let available = true
    private static let controller = SPUStandardUpdaterController(
        startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
    static func start() { _ = controller }
    static func checkNow() { controller.checkForUpdates(nil) }
}
#else
@MainActor
enum AppUpdater {
    static let available = false
    static func start() {}
    static func checkNow() {}
}
#endif
