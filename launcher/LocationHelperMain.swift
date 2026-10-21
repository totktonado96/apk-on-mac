// LocationHelperMain.swift -- "Mac.apk Location", the process that talks to
// CoreLocation on behalf of every Android app's runtime (2026-10-06).
//
// WHY A SEPARATE APP. macOS shows its Location Services prompt only for a
// process whose executable IS an app bundle's CFBundleExecutable. The runtime
// is not one: an installed app's stub execs the SHARED runtime through a
// symlink, and the real binary lives in ~/Library/Application Support/Mac.apk/
// runtime. CoreLocationAgent logged, for every request the runtime made:
//   Getting bundleRecord failed ... "This process is not the executable of a bundle."
//   client bundle is NULL. Skip showing AuthPrompt
// so no prompt ever appeared, the authorization stayed NotDetermined, and the
// requesting app waited (owner report, 2026-10-06: "kinda freezes after hitting allow").
// A probe binary measured the rule the same night: run bare, the same code was
// skipped; placed as the executable of a .app and run directly (no
// LaunchServices launch), it got "Showing alert for app".
//
// So this tiny bundle holds the CLLocationManager, and the runtime
// (runtime/src/location_bridge.mm) runs it as a child and speaks a line
// protocol over its stdin / stdout:
//   runtime -> helper   auth | start <0|1 reduced> | stop | cached
//   helper  -> runtime  auth <CLAuthorizationStatus> <0|1 reduced>
//                       fix <lat> <lon> <ellAlt> <mslAlt> <hAcc> <vAcc> <speed>
//                           <speedAcc> <course> <courseAcc> <timeMs> <0|1 simulated>
//                       cached none | cached <same 12 fields as fix>
//                       error <CLError code>
// macOS asks once for "Mac.apk Location" (the identity locationd keys it by is
// this bundle's), and Mac.apk's own per-app dialog stays in front of it.
// It exits when its stdin closes, i.e. when the runtime that started it dies.

import CoreLocation
import Foundation

final class Helper: NSObject, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    var updating = false

    override init() {
        super.init()
        manager.delegate = self   // CoreLocation then reports the current status at once
    }

    func send(_ line: String) {
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }

    func fields(_ l: CLLocation) -> String {
        let sim = l.sourceInformation?.isSimulatedBySoftware == true ? 1 : 0
        let t = Int64((l.timestamp.timeIntervalSince1970 * 1000).rounded())
        return [l.coordinate.latitude, l.coordinate.longitude, l.ellipsoidalAltitude,
                l.altitude, l.horizontalAccuracy, l.verticalAccuracy, l.speed,
                l.speedAccuracy, l.course, l.courseAccuracy]
            .map { "\($0)" }.joined(separator: " ") + " \(t) \(sim)"
    }

    func sendAuth() {
        let reduced = manager.accuracyAuthorization == .reducedAccuracy ? 1 : 0
        send("auth \(manager.authorizationStatus.rawValue) \(reduced)")
    }

    func handle(_ line: String) {
        let parts = line.split(separator: " ").map(String.init)
        guard let cmd = parts.first else { return }
        switch cmd {
        case "auth":
            if manager.authorizationStatus == .notDetermined {
                manager.requestWhenInUseAuthorization()
            } else {
                sendAuth()
            }
        case "start":
            let reduced = parts.count > 1 && parts[1] == "1"
            // COARSE without FINE on Android is CoreLocation's reduced accuracy.
            manager.desiredAccuracy = reduced ? kCLLocationAccuracyReduced : kCLLocationAccuracyBest
            manager.distanceFilter = kCLDistanceFilterNone
            if manager.authorizationStatus == .notDetermined {
                manager.requestWhenInUseAuthorization()
            }
            if !updating {
                updating = true
                manager.startUpdatingLocation()
            }
            // The cached fix, so a fresh session is not blind until the next
            // Wi-Fi scan. Not in reduced mode: it may be a precise fix.
            if !reduced, let l = manager.location, l.horizontalAccuracy >= 0 {
                send("fix " + fields(l))
            }
        case "stop":
            if updating {
                updating = false
                manager.stopUpdatingLocation()
            }
        case "cached":
            if let l = manager.location, l.horizontalAccuracy >= 0 {
                send("cached " + fields(l))
            } else {
                send("cached none")
            }
        default:
            break
        }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        sendAuth()
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        for l in locations where l.horizontalAccuracy >= 0 { send("fix " + fields(l)) }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        send("error \((error as NSError).code)")
    }
}

@main
enum LocationHelperMain {
    static func main() {
        signal(SIGPIPE, SIG_IGN)   // a runtime that died mid-write must not kill us noisily
        let helper = Helper()
        var pending = Data()
        FileHandle.standardInput.readabilityHandler = { h in
            let chunk = h.availableData
            if chunk.isEmpty { exit(0) }   // the runtime is gone
            DispatchQueue.main.async {
                pending.append(chunk)
                while let nl = pending.firstIndex(of: 0x0A) {
                    let line = String(decoding: pending[pending.startIndex..<nl], as: UTF8.self)
                    pending.removeSubrange(pending.startIndex...nl)
                    helper.handle(line.trimmingCharacters(in: .whitespaces))
                }
            }
        }
        // CLLocationManager delivers its delegate calls on the run loop of the
        // thread that created it: this one.
        RunLoop.main.run()
    }
}
