import Foundation
import QuickLookThumbnailing
import CoreGraphics

@objc(ApkThumbnailProvider)
final class ApkThumbnailProvider: QLThumbnailProvider {
    override func provideThumbnail(for request: QLFileThumbnailRequest,
                                   _ handler: @escaping (QLThumbnailReply?, Error?) -> Void) {
        guard let info = loadApkInfo(url: request.fileURL), let icon = info.icon else {
            handler(nil, CocoaError(.fileReadCorruptFile)); return
        }
        let size = request.maximumSize
        let side = min(size.width, size.height)
        let w = side, h = side
        handler(QLThumbnailReply(contextSize: CGSize(width: w, height: h), drawing: { ctx in
            ctx.interpolationQuality = .high
            ctx.draw(icon, in: CGRect(x: 0, y: 0, width: w, height: h))
            return true
        }), nil)
    }
}
