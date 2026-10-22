// share_bridge.mm -- com.macapk.loader.ShareSheet <-> NSSharingServicePicker.
//
// Android's ACTION_SEND chooser lists the apps that can take a share. On the Mac
// the same role is the system share sheet (Mail, Messages, AirDrop, Notes, ...),
// which is NSSharingServicePicker. Items are the share's text and file URLs.
//
// Threading: the picker is AppKit UI, so it is presented on the main queue; the
// JNI call returns as soon as the work is queued. The picker is retained until
// the user picks a service or dismisses the menu (the delegate callback fires
// with a nil service for a dismissal), the way AppKit expects it to stay alive.
//
// MRC, like the other .mm bridges in this target.
#import <AppKit/AppKit.h>
#include <jni.h>
#include <cstdio>

@interface MacApkShareDelegate : NSObject <NSSharingServicePickerDelegate>
@end
@implementation MacApkShareDelegate
- (void)sharingServicePicker:(NSSharingServicePicker*)picker
         didChooseSharingService:(NSSharingService*)service {
    [picker release];   // balances the retain taken when it was shown
}
@end

namespace macapk {
namespace share {
namespace {

jboolean JNICALL Share_nativeShare(JNIEnv* env, jclass, jstring jsubject, jstring jtext,
                                   jobjectArray jpaths) {
    NSMutableArray* items = [[NSMutableArray alloc] init];
    auto str = [&](jstring js) -> NSString* {
        if (!js) return @"";
        const jchar* c = env->GetStringChars(js, nullptr);
        NSString* s = [NSString stringWithCharacters:(const unichar*)c
                                              length:(NSUInteger)env->GetStringLength(js)];
        env->ReleaseStringChars(js, c);
        return s;
    };
    NSString* subject = str(jsubject);
    NSString* text = str(jtext);
    if (text.length > 0 || subject.length > 0) {
        // NSSharingService has no subject slot for a plain string item, so a
        // subject that the text does not already carry leads the message.
        NSString* msg = (subject.length > 0 && ![text hasPrefix:subject])
            ? (text.length > 0 ? [NSString stringWithFormat:@"%@\n\n%@", subject, text] : subject)
            : text;
        [items addObject:msg];
    }
    jsize n = jpaths ? env->GetArrayLength(jpaths) : 0;
    for (jsize i = 0; i < n; i++) {
        jstring jp = (jstring)env->GetObjectArrayElement(jpaths, i);
        NSString* p = str(jp);
        if (jp) env->DeleteLocalRef(jp);
        if (p.length > 0) [items addObject:[NSURL fileURLWithPath:p]];
    }
    if (items.count == 0) { [items release]; return JNI_FALSE; }

    dispatch_async(dispatch_get_main_queue(), ^{
        static MacApkShareDelegate* delegate = [[MacApkShareDelegate alloc] init];
        NSWindow* w = [NSApp keyWindow];
        if (!w) w = [NSApp mainWindow];
        if (!w) for (NSWindow* c in [NSApp windows]) if (c.isVisible) { w = c; break; }
        NSView* v = w.contentView;
        if (!v) { NSBeep(); return; }
        NSSharingServicePicker* picker = [[NSSharingServicePicker alloc] initWithItems:items];
        picker.delegate = delegate;   // the picker (+1 from alloc) is released in the delegate
        NSRect b = v.bounds;
        // The window centre, a 1pt anchor so the menu opens in the middle.
        [picker showRelativeToRect:NSMakeRect(NSMidX(b), NSMidY(b), 1, 1)
                            ofView:v
                     preferredEdge:NSRectEdgeMinY];
    });
    [items release];   // the block holds its own retain (MRC copies captured objects)
    return JNI_TRUE;
}

const JNINativeMethod kMethods[] = {
    {const_cast<char*>("nativeShare"),
     const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z"),
     reinterpret_cast<void*>(Share_nativeShare)},
};

}  // namespace

// Soft-fails: a jar without ShareSheet just has no share sheet this run.
void RegisterShareBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/ShareSheet");
    if (!cls) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] share: no ShareSheet in this framework jar; "
                     "the share sheet is not bridged this run\n");
        return;
    }
    if (env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] share: RegisterNatives(ShareSheet) failed\n");
    }
    env->DeleteLocalRef(cls);
}

}  // namespace share
}  // namespace macapk
