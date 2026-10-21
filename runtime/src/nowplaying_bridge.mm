// nowplaying_bridge.mm -- android.media.session.MacApkNowPlaying <-> macOS
// Now Playing (MPNowPlayingInfoCenter) and its transport (MPRemoteCommandCenter).
//
// The app's active MediaSession is what a device's system media controls, lock
// screen and media keys talk to (MediaSessionService). On the Mac that surface
// is the Now Playing widget in Control Center / the menu bar, plus the keyboard
// media keys and AirPods controls that MPRemoteCommandCenter delivers, so the
// session is published there (decision-ladder rung 1). MediaPlayer.framework is
// in the dyld shared cache; nothing is bundled.
//
// Threading: MPNowPlayingInfoCenter and MPRemoteCommandCenter are touched on the
// main queue only. A command handler runs on the main queue too and calls back
// into Java on that thread (attached as a daemon); the Java side posts the
// Callback onto the session's own Handler, so the app sees its callbacks on the
// thread it asked for, as on a device.
//
// MRC, like the other .mm bridges in this target.
#import <AppKit/AppKit.h>
#import <MediaPlayer/MediaPlayer.h>
#include <jni.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace macapk {
namespace nowplaying {
namespace {

JavaVM*   g_vm = nullptr;
jclass    g_cls = nullptr;          // global ref to android.media.session.MacApkNowPlaying
jmethodID g_on_command = nullptr;
bool      g_commands_registered = false;   // main queue only
NSImage*  g_art = nil;                     // main queue only, retained
bool      g_published = false;             // main queue only

// Commands, matching MacApkNowPlaying.CMD_*.
enum { CMD_PLAY = 1, CMD_PAUSE = 2, CMD_TOGGLE = 3, CMD_NEXT = 4,
       CMD_PREVIOUS = 5, CMD_SEEK = 6, CMD_STOP = 7 };

// android.media.session.PlaybackState.ACTION_* (AOSP PlaybackState.java).
constexpr jlong ACTION_STOP = 1 << 0;
constexpr jlong ACTION_PAUSE = 1 << 1;
constexpr jlong ACTION_PLAY = 1 << 2;
constexpr jlong ACTION_SKIP_TO_PREVIOUS = 1 << 4;
constexpr jlong ACTION_SKIP_TO_NEXT = 1 << 5;
constexpr jlong ACTION_SEEK_TO = 1 << 8;
constexpr jlong ACTION_PLAY_PAUSE = 1 << 9;

bool TraceOn() {
    static int on = -1;
    if (on < 0) {
        const char* e = std::getenv("MACAPK_TRACE_NOW_PLAYING");
        on = (e && *e && std::strcmp(e, "0") != 0) ? 1 : 0;
    }
    return on == 1;
}

JNIEnv* Env() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint r = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_21);
    if (r == JNI_EDETACHED &&
        g_vm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env), nullptr) != JNI_OK) {
        return nullptr;
    }
    return env;
}

void Send(int cmd, double arg) {
    if (TraceOn()) std::fprintf(stderr, "[nowplaying] remote command %d (%.3f)\n", cmd, arg);
    JNIEnv* env = Env();
    if (!env || !g_cls || !g_on_command) return;
    env->CallStaticVoidMethod(g_cls, g_on_command, (jint)cmd, (jdouble)arg);
    if (env->ExceptionCheck()) {
        std::fprintf(stderr, "[W] nowplaying: Java threw in onRemoteCommand\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void RegisterCommandsOnMain() {
    if (g_commands_registered) return;
    g_commands_registered = true;
    MPRemoteCommandCenter* cc = [MPRemoteCommandCenter sharedCommandCenter];
    [cc.playCommand addTargetWithHandler:^MPRemoteCommandHandlerStatus(MPRemoteCommandEvent*) {
        Send(CMD_PLAY, 0); return MPRemoteCommandHandlerStatusSuccess; }];
    [cc.pauseCommand addTargetWithHandler:^MPRemoteCommandHandlerStatus(MPRemoteCommandEvent*) {
        Send(CMD_PAUSE, 0); return MPRemoteCommandHandlerStatusSuccess; }];
    [cc.togglePlayPauseCommand addTargetWithHandler:^MPRemoteCommandHandlerStatus(MPRemoteCommandEvent*) {
        Send(CMD_TOGGLE, 0); return MPRemoteCommandHandlerStatusSuccess; }];
    [cc.nextTrackCommand addTargetWithHandler:^MPRemoteCommandHandlerStatus(MPRemoteCommandEvent*) {
        Send(CMD_NEXT, 0); return MPRemoteCommandHandlerStatusSuccess; }];
    [cc.previousTrackCommand addTargetWithHandler:^MPRemoteCommandHandlerStatus(MPRemoteCommandEvent*) {
        Send(CMD_PREVIOUS, 0); return MPRemoteCommandHandlerStatusSuccess; }];
    [cc.stopCommand addTargetWithHandler:^MPRemoteCommandHandlerStatus(MPRemoteCommandEvent*) {
        Send(CMD_STOP, 0); return MPRemoteCommandHandlerStatusSuccess; }];
    [cc.changePlaybackPositionCommand addTargetWithHandler:^MPRemoteCommandHandlerStatus(MPRemoteCommandEvent* e) {
        if (![e isKindOfClass:[MPChangePlaybackPositionCommandEvent class]])
            return MPRemoteCommandHandlerStatusCommandFailed;
        Send(CMD_SEEK, ((MPChangePlaybackPositionCommandEvent*)e).positionTime);
        return MPRemoteCommandHandlerStatusSuccess; }];
}

// Enable each command the way the session's PlaybackState advertises it: a
// device's system controls only offer what getActions() includes. Play and
// pause are always offered once a session is published (every player answers
// them; MediaSessionCompat adds them implicitly too), so the keyboard
// play/pause key works even for a session that never sets actions.
void ApplyActionsOnMain(jlong actions) {
    MPRemoteCommandCenter* cc = [MPRemoteCommandCenter sharedCommandCenter];
    cc.playCommand.enabled = YES;
    cc.pauseCommand.enabled = YES;
    cc.togglePlayPauseCommand.enabled = YES;
    cc.nextTrackCommand.enabled = (actions & ACTION_SKIP_TO_NEXT) != 0;
    cc.previousTrackCommand.enabled = (actions & ACTION_SKIP_TO_PREVIOUS) != 0;
    cc.stopCommand.enabled = (actions & ACTION_STOP) != 0;
    cc.changePlaybackPositionCommand.enabled = (actions & ACTION_SEEK_TO) != 0;
    (void)ACTION_PLAY; (void)ACTION_PAUSE; (void)ACTION_PLAY_PAUSE;
}

NSString* Str(JNIEnv* env, jstring s) {
    if (!s) return nil;
    const char* c = env->GetStringUTFChars(s, nullptr);
    if (!c) return nil;
    NSString* out = [[NSString alloc] initWithUTF8String:c];
    env->ReleaseStringUTFChars(s, c);
    return [out autorelease];
}

void JNICALL NowPlaying_nativeUpdate(JNIEnv* env, jclass, jstring title, jstring artist,
                                     jstring album, jdouble duration, jdouble elapsed,
                                     jdouble rate, jint state, jlong actions,
                                     jbyteArray png, jboolean artChanged) {
    NSString* t = [Str(env, title) retain];
    NSString* a = [Str(env, artist) retain];
    NSString* al = [Str(env, album) retain];
    NSData* artData = nil;
    if (png) {
        jsize n = env->GetArrayLength(png);
        if (n > 0) {
            jbyte* b = env->GetByteArrayElements(png, nullptr);
            if (b) {
                artData = [[NSData alloc] initWithBytes:b length:(NSUInteger)n];
                env->ReleaseByteArrayElements(png, b, JNI_ABORT);
            }
        }
    }
    const bool changed = artChanged == JNI_TRUE;
    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            RegisterCommandsOnMain();
            if (changed) {
                [g_art release];
                g_art = artData ? [[NSImage alloc] initWithData:artData] : nil;
            }
            NSMutableDictionary* info = [NSMutableDictionary dictionary];
            if (t) info[MPMediaItemPropertyTitle] = t;
            if (a) info[MPMediaItemPropertyArtist] = a;
            if (al) info[MPMediaItemPropertyAlbumTitle] = al;
            if (duration > 0) info[MPMediaItemPropertyPlaybackDuration] = @(duration);
            info[MPNowPlayingInfoPropertyElapsedPlaybackTime] = @(elapsed);
            info[MPNowPlayingInfoPropertyPlaybackRate] = @(rate);
            info[MPNowPlayingInfoPropertyMediaType] = @(MPNowPlayingInfoMediaTypeAudio);
            if (g_art) {
                NSImage* img = g_art;
                info[MPMediaItemPropertyArtwork] =
                    [[[MPMediaItemArtwork alloc] initWithBoundsSize:img.size
                        requestHandler:^NSImage*(CGSize) { return img; }] autorelease];
            }
            MPNowPlayingInfoCenter* c = [MPNowPlayingInfoCenter defaultCenter];
            c.nowPlayingInfo = info;
            MPNowPlayingPlaybackState ps = MPNowPlayingPlaybackStateUnknown;
            switch (state) {
                case 1: ps = MPNowPlayingPlaybackStatePlaying; break;
                case 2: ps = MPNowPlayingPlaybackStatePaused; break;
                case 3: ps = MPNowPlayingPlaybackStateStopped; break;
                default: break;
            }
            c.playbackState = ps;
            ApplyActionsOnMain(actions);
            // Untraced runs log every TRANSITION of what is shown (title, artist,
            // state, artwork), not just the first publish: a log holding only the
            // first, empty, publish of a session read as "the bridge never
            // updated" when it simply had not been asked to say so.
            static NSString* s_title = nil; static NSString* s_artist = nil;
            static int s_state = -1; static bool s_art = false;
            const bool moved = !g_published || state != s_state || (g_art != nil) != s_art
                || !((t == nil && s_title == nil) || [t isEqualToString:s_title])
                || !((a == nil && s_artist == nil) || [a isEqualToString:s_artist]);
            if (TraceOn() || moved) {
                std::fprintf(stderr, "[nowplaying] %s \"%s\" / \"%s\" state=%d pos=%.1f/%.1f rate=%.2f art=%s\n",
                             g_published ? "update" : "published",
                             t ? t.UTF8String : "", a ? a.UTF8String : "", (int)state,
                             (double)elapsed, (double)duration, (double)rate, g_art ? "yes" : "no");
            }
            if (moved) {
                [s_title release]; s_title = [t copy];
                [s_artist release]; s_artist = [a copy];
                s_state = (int)state; s_art = g_art != nil;
            }
            g_published = true;
        }
        [t release]; [a release]; [al release]; [artData release];
    });
}

void JNICALL NowPlaying_nativeClear(JNIEnv*, jclass) {
    dispatch_async(dispatch_get_main_queue(), ^{
        MPNowPlayingInfoCenter* c = [MPNowPlayingInfoCenter defaultCenter];
        c.nowPlayingInfo = nil;
        c.playbackState = MPNowPlayingPlaybackStateStopped;
        [g_art release];
        g_art = nil;
        if (g_published) std::fprintf(stderr, "[nowplaying] cleared\n");
        g_published = false;
    });
}

const JNINativeMethod kMethods[] = {
    {const_cast<char*>("nativeUpdate"),
     const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;DDDIJ[BZ)V"),
     reinterpret_cast<void*>(NowPlaying_nativeUpdate)},
    {const_cast<char*>("nativeClear"), const_cast<char*>("()V"),
     reinterpret_cast<void*>(NowPlaying_nativeClear)},
};

}  // namespace

// Soft-fails like the clipboard / location registrations: a framework jar older
// than this binary simply has no Now Playing bridge this run.
void RegisterNowPlayingBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("android/media/session/MacApkNowPlaying");
    if (!cls) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] nowplaying: no MacApkNowPlaying in this framework jar; "
                     "Now Playing is not bridged this run\n");
        return;
    }
    if (env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] nowplaying: RegisterNatives(MacApkNowPlaying) failed; "
                     "Now Playing is not bridged this run\n");
        env->DeleteLocalRef(cls);
        return;
    }
    g_on_command = env->GetStaticMethodID(cls, "onRemoteCommand", "(ID)V");
    if (!g_on_command) {
        env->ExceptionClear();
        std::fprintf(stderr, "[I] nowplaying: onRemoteCommand(ID)V missing; "
                     "Now Playing shows but takes no commands\n");
    }
    env->GetJavaVM(&g_vm);
    g_cls = (jclass)env->NewGlobalRef(cls);
    env->DeleteLocalRef(cls);
}

}  // namespace nowplaying
}  // namespace macapk
