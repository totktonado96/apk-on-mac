// Host game controllers -> Android gamepads: the native half of
// com.macapk.loader.GamepadBridge (MACAPK_GAMEPAD, default ON; 2026-10-02;
// docs/host-game-controllers_2026-10-02.md).
//
// Rung 1 of the decision ladder: on Android the kernel's HID drivers (xpad,
// hid-playstation, hid-nintendo, ...) turn each controller into an evdev device
// that InputReader maps; on macOS GameController.framework already does that
// abstraction for Xbox, PlayStation, Switch and MFi controllers, so we route to
// it and send Java a neutral snapshot -- which buttons are held and the eight
// axes in ANDROID's convention -- and the Java side does what InputReader,
// InputDispatcher and ViewRootImpl do with it.
//
// Threading: GameController delivers connect/disconnect notifications and every
// valueChangedHandler on the main queue (GCController.handlerQueue defaults to
// it), i.e. the AppKit thread, which is the thread host keystrokes reach Java on
// (cocoa_bridge.mm dispatchKeyRawAction). Java routes from there exactly as it
// does for a key. shouldMonitorBackgroundEvents keeps its macOS 11.3+ default
// (NO): a controller drives the frontmost app only, which is Android's "the
// focused window gets the input".
//
// Built with ARC (CMakeLists.txt): the handlers are blocks capturing controllers.

#import <Foundation/Foundation.h>
#import <GameController/GameController.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <jni.h>
#include <cstdio>
#include <cstdlib>

namespace macapk {
namespace gamepad {

namespace {

// Keep in step with GamepadBridge.BTN_* / CAP_*.
enum : int {
    BTN_A = 1 << 0, BTN_B = 1 << 1, BTN_X = 1 << 2, BTN_Y = 1 << 3,
    BTN_L1 = 1 << 4, BTN_R1 = 1 << 5, BTN_L2 = 1 << 6, BTN_R2 = 1 << 7,
    BTN_THUMBL = 1 << 8, BTN_THUMBR = 1 << 9, BTN_START = 1 << 10,
    BTN_SELECT = 1 << 11, BTN_MODE = 1 << 12,
};
enum : int { CAP_OPTIONS = 1, CAP_HOME = 2, CAP_THUMB_BUTTONS = 4 };

JavaVM*   g_vm = nullptr;
jclass    g_cls = nullptr;          // global ref to com.macapk.loader.GamepadBridge
jmethodID g_on_connected = nullptr;
jmethodID g_on_disconnected = nullptr;
jmethodID g_on_state = nullptr;
bool      g_started = false;
// Controllers we registered, so a disconnect is reported only for those and a
// handle (the controller's address) cannot be reused while Java still holds it.
NSMutableSet<GCController*>* g_known = nil;

JNIEnv* Env() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint r = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_21);
    if (r == JNI_EDETACHED &&
        g_vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) != JNI_OK) {
        return nullptr;
    }
    return env;
}

void ClearException(JNIEnv* env, const char* what) {
    if (env->ExceptionCheck()) {
        std::fprintf(stderr, "[W] gamepad: Java threw in %s\n", what);
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

jlong Handle(GCController* c) { return (jlong)(intptr_t)(__bridge void*)c; }

// ---- vendor / product ids ---------------------------------------------------
//
// Android's InputDevice.getVendorId()/getProductId() are the HID ids, and engines
// use them (SDL builds its controller GUID from them to look up a mapping).
// GameController does not expose them, so read them from the IORegistry: the
// IOHIDDevice whose Product string is the controller's vendorName, among the
// devices whose primary usage is a game controller (Generic Desktop page 0x01:
// Joystick 0x04, Game Pad 0x05, Multi-axis Controller 0x08). Reading registry
// properties opens nothing, so it needs no Input Monitoring permission. Ids we
// cannot attribute stay 0, which is AOSP's "not available" value.
struct HidIds { int vendor = 0; int product = 0; NSString* serial = nil; };

int IntProp(io_service_t s, CFStringRef key) {
    int v = 0;
    CFTypeRef p = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (p) {
        if (CFGetTypeID(p) == CFNumberGetTypeID()) CFNumberGetValue((CFNumberRef)p, kCFNumberIntType, &v);
        CFRelease(p);
    }
    return v;
}

NSString* StrProp(io_service_t s, CFStringRef key) {
    CFTypeRef p = IORegistryEntryCreateCFProperty(s, key, kCFAllocatorDefault, 0);
    if (!p) return nil;
    NSString* out = nil;
    if (CFGetTypeID(p) == CFStringGetTypeID()) out = (__bridge_transfer NSString*)p;
    else CFRelease(p);
    return out;
}

HidIds FindHidIds(GCController* c) {
    HidIds best;
    io_iterator_t it = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(kIOHIDDeviceKey), &it)
            != KERN_SUCCESS) {
        return best;
    }
    NSString* want = c.vendorName;
    int gamepads = 0, nameMatches = 0;
    HidIds only, named;
    io_service_t s;
    while ((s = IOIteratorNext(it)) != IO_OBJECT_NULL) {
        const int page = IntProp(s, CFSTR(kIOHIDPrimaryUsagePageKey));
        const int usage = IntProp(s, CFSTR(kIOHIDPrimaryUsageKey));
        if (page == 0x01 && (usage == 0x04 || usage == 0x05 || usage == 0x08)) {
            HidIds ids;
            ids.vendor = IntProp(s, CFSTR(kIOHIDVendorIDKey));
            ids.product = IntProp(s, CFSTR(kIOHIDProductIDKey));
            ids.serial = StrProp(s, CFSTR(kIOHIDSerialNumberKey));
            NSString* product = StrProp(s, CFSTR(kIOHIDProductKey));
            gamepads++;
            only = ids;
            if (want && product && [product caseInsensitiveCompare:want] == NSOrderedSame) {
                if (nameMatches == 0) {
                    named = ids;
                } else if (named.vendor != ids.vendor || named.product != ids.product) {
                    named.vendor = named.product = -1;   // same name, different ids: unattributable
                }
                nameMatches++;
            }
        }
        IOObjectRelease(s);
    }
    IOObjectRelease(it);
    if (nameMatches == 1) {
        best = named;
    } else if (nameMatches > 1 && named.vendor >= 0) {
        // Two identical controllers: the ids are right for both, but which
        // serial is whose cannot be told from here, so leave it out.
        best.vendor = named.vendor;
        best.product = named.product;
    } else if (nameMatches == 0 && gamepads == 1 && [GCController controllers].count == 1) {
        // One game controller on the bus and one connected: it is this one.
        best = only;
    }
    return best;
}

// ---- state ------------------------------------------------------------------

void SendState(GCController* c) {
    GCExtendedGamepad* g = c.extendedGamepad;
    JNIEnv* env = Env();
    if (!g || !env || !g_on_state) return;
    int b = 0;
    if (g.buttonA.isPressed) b |= BTN_A;
    if (g.buttonB.isPressed) b |= BTN_B;
    if (g.buttonX.isPressed) b |= BTN_X;
    if (g.buttonY.isPressed) b |= BTN_Y;
    if (g.leftShoulder.isPressed) b |= BTN_L1;
    if (g.rightShoulder.isPressed) b |= BTN_R1;
    if (g.leftTrigger.isPressed) b |= BTN_L2;
    if (g.rightTrigger.isPressed) b |= BTN_R2;
    if (g.leftThumbstickButton.isPressed) b |= BTN_THUMBL;
    if (g.rightThumbstickButton.isPressed) b |= BTN_THUMBR;
    if (g.buttonMenu.isPressed) b |= BTN_START;
    if (g.buttonOptions.isPressed) b |= BTN_SELECT;
    if (g.buttonHome.isPressed) b |= BTN_MODE;
    // GameController's y axes are up-positive; Android's AXIS_Y / AXIS_RZ /
    // AXIS_HAT_Y are down-positive (a pushed-up stick reads -1).
    env->CallStaticVoidMethod(g_cls, g_on_state, Handle(c), (jint)b,
        (jfloat)g.leftThumbstick.xAxis.value, (jfloat)-g.leftThumbstick.yAxis.value,
        (jfloat)g.rightThumbstick.xAxis.value, (jfloat)-g.rightThumbstick.yAxis.value,
        (jfloat)g.leftTrigger.value, (jfloat)g.rightTrigger.value,
        (jfloat)g.dpad.xAxis.value, (jfloat)-g.dpad.yAxis.value);
    ClearException(env, "onState");
}

void Connect(GCController* c) {
    if (!c || [g_known containsObject:c]) return;
    GCExtendedGamepad* g = c.extendedGamepad;
    NSString* name = c.vendorName ?: c.productCategory;
    if (!g) {
        // A micro gamepad (Siri Remote) or a non-gamepad profile: not an
        // Android gamepad, so it is not registered.
        std::fprintf(stderr, "[I] gamepad: \"%s\" has no extended gamepad profile; not bridged\n",
                     name ? name.UTF8String : "?");
        return;
    }
    JNIEnv* env = Env();
    if (!env) return;
    int caps = 0;
    if (g.buttonOptions) caps |= CAP_OPTIONS;
    if (g.buttonHome) caps |= CAP_HOME;
    if (g.leftThumbstickButton && g.rightThumbstickButton) caps |= CAP_THUMB_BUTTONS;
    HidIds ids = FindHidIds(c);
    jstring jname = env->NewStringUTF(name ? name.UTF8String : "");
    jstring juniq = env->NewStringUTF(ids.serial ? ids.serial.UTF8String : "");
    jint number = env->CallStaticIntMethod(g_cls, g_on_connected, Handle(c), jname,
                                           (jint)ids.vendor, (jint)ids.product, juniq, (jint)caps);
    env->DeleteLocalRef(jname);
    env->DeleteLocalRef(juniq);
    if (env->ExceptionCheck()) { ClearException(env, "onConnected"); return; }
    [g_known addObject:c];
    // EventHub lights the controller's LED for its controller number
    // (setLedForControllerLocked); GameController's player index is that LED.
    c.playerIndex = (number >= 1 && number <= 4) ? (GCControllerPlayerIndex)(number - 1)
                                                 : GCControllerPlayerIndexUnset;
    // Android hands BUTTON_MODE to the app first (its HOME fallback only runs
    // when the app declines it). AlwaysReceive keeps macOS's own Home gesture
    // and lets us read the press as well.
    if (g.buttonHome) g.buttonHome.preferredSystemGestureState = GCSystemGestureStateAlwaysReceive;
    __weak GCController* weak = c;
    g.valueChangedHandler = ^(GCExtendedGamepad*, GCControllerElement*) {
        GCController* strong = weak;
        if (strong) SendState(strong);
    };
    std::fprintf(stderr, "[I] gamepad: connected \"%s\" (%s) vendor=0x%04x product=0x%04x player=%d\n",
                 name ? name.UTF8String : "?", c.productCategory.UTF8String ?: "?",
                 ids.vendor, ids.product, (int)number);
    SendState(c);
}

void Disconnect(GCController* c) {
    if (!c || ![g_known containsObject:c]) return;
    c.extendedGamepad.valueChangedHandler = nil;
    JNIEnv* env = Env();
    if (env) {
        env->CallStaticVoidMethod(g_cls, g_on_disconnected, Handle(c));
        ClearException(env, "onDisconnected");
    }
    [g_known removeObject:c];
}

// ---- simulated controller (harness only) -----------------------------------
//
// MACAPK_GAMEPAD_SIMULATE=<script>: no physical controller can be conjured on a
// test machine (IOHIDUserDevice needs a restricted entitlement), so this drives
// a GameController SNAPSHOT controller (+controllerWithExtendedGamepad, whose
// elements accept -setValue:) through the SAME Connect / SendState / Disconnect
// a real one takes. Values are in GameController's convention (y up-positive),
// so the sign flip in SendState is exercised too. A snapshot never fires its
// valueChangedHandler, so each change calls SendState itself. Lines:
//   sleep <ms> | waitfile <path> | connect | disconnect
//   btn a|b|x|y|l1|r1|l2|r2|thumbl|thumbr|menu|options|home <0..1>
//   axis lx|ly|rx|ry|lt|rt|dx|dy <value>
// Unset, nothing here runs. debug/gamepad_sim.sh writes these scripts.
GCController* g_sim = nil;

GCControllerElement* SimElement(GCExtendedGamepad* g, NSString* n) {
    NSDictionary<NSString*, GCControllerElement*>* m = @{
        @"a": g.buttonA, @"b": g.buttonB, @"x": g.buttonX, @"y": g.buttonY,
        @"l1": g.leftShoulder, @"r1": g.rightShoulder,
        @"l2": g.leftTrigger, @"r2": g.rightTrigger,
        @"lt": g.leftTrigger, @"rt": g.rightTrigger,
        @"thumbl": g.leftThumbstickButton, @"thumbr": g.rightThumbstickButton,
        @"menu": g.buttonMenu, @"options": g.buttonOptions, @"home": g.buttonHome,
        @"lx": g.leftThumbstick.xAxis, @"ly": g.leftThumbstick.yAxis,
        @"rx": g.rightThumbstick.xAxis, @"ry": g.rightThumbstick.yAxis,
        @"dx": g.dpad.xAxis, @"dy": g.dpad.yAxis,
    };
    return m[n];
}

void SimLine(NSString* line) {
    std::fprintf(stderr, "[I] gamepad-sim: %s\n", line.UTF8String);
    NSArray<NSString*>* t = [line componentsSeparatedByCharactersInSet:
                             [NSCharacterSet whitespaceCharacterSet]];
    if (t.count == 0) return;
    if ([t[0] isEqualToString:@"connect"]) {
        if (!g_sim) g_sim = [GCController controllerWithExtendedGamepad];
        Connect(g_sim);
    } else if ([t[0] isEqualToString:@"disconnect"]) {
        Disconnect(g_sim);
    } else if (t.count >= 3 && g_sim) {
        GCControllerElement* e = SimElement(g_sim.extendedGamepad, t[1]);
        if ([e isKindOfClass:[GCControllerButtonInput class]]) {
            [(GCControllerButtonInput*)e setValue:t[2].floatValue];
        } else if ([e isKindOfClass:[GCControllerAxisInput class]]) {
            [(GCControllerAxisInput*)e setValue:t[2].floatValue];
        } else {
            std::fprintf(stderr, "[W] gamepad-sim: unknown element in \"%s\"\n", line.UTF8String);
            return;
        }
        SendState(g_sim);
    }
}

// The script runs line by line on the main queue: `sleep` re-schedules the
// rest, `waitfile <path>` polls (every 200 ms) until that file exists, so a
// harness can release a step at a moment of its own choosing.
NSArray<NSString*>* g_sim_lines = nil;

void SimNext(NSUInteger i) {
    for (; i < g_sim_lines.count; i++) {
        NSString* line = [g_sim_lines[i] stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        if (line.length == 0 || [line hasPrefix:@"#"]) continue;
        if ([line hasPrefix:@"sleep "]) {
            double ms = [line substringFromIndex:6].doubleValue;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(ms * NSEC_PER_MSEC)),
                           dispatch_get_main_queue(), ^{ SimNext(i + 1); });
            return;
        }
        if ([line hasPrefix:@"waitfile "]) {
            NSString* f = [[line substringFromIndex:9] stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceCharacterSet]];
            if (![[NSFileManager defaultManager] fileExistsAtPath:f]) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(200 * NSEC_PER_MSEC)),
                               dispatch_get_main_queue(), ^{ SimNext(i); });
                return;
            }
            std::fprintf(stderr, "[I] gamepad-sim: %s (released)\n", line.UTF8String);
            continue;
        }
        SimLine(line);
    }
    std::fprintf(stderr, "[I] gamepad-sim: script done\n");
}

void RunSimulation(NSString* path) {
    NSString* text = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (!text) {
        std::fprintf(stderr, "[W] gamepad-sim: cannot read %s\n", path.UTF8String);
        return;
    }
    g_sim_lines = [text componentsSeparatedByString:@"\n"];
    std::fprintf(stderr, "[I] gamepad-sim: running %s\n", path.UTF8String);
    SimNext(0);
}

void Start() {
    if (g_started) return;
    g_started = true;
    g_known = [NSMutableSet set];
    NSNotificationCenter* nc = [NSNotificationCenter defaultCenter];
    NSOperationQueue* main = [NSOperationQueue mainQueue];
    [nc addObserverForName:GCControllerDidConnectNotification object:nil queue:main
                usingBlock:^(NSNotification* n) { Connect((GCController*)n.object); }];
    [nc addObserverForName:GCControllerDidDisconnectNotification object:nil queue:main
                usingBlock:^(NSNotification* n) { Disconnect((GCController*)n.object); }];
    NSArray<GCController*>* now = [GCController controllers];
    std::fprintf(stderr, "[I] gamepad: watching GameController.framework (%lu connected)\n",
                 (unsigned long)now.count);
    for (GCController* c in now) Connect(c);
    if (const char* sim = getenv("MACAPK_GAMEPAD_SIMULATE")) {
        if (*sim) RunSimulation([NSString stringWithUTF8String:sim]);
    }
}

void JNICALL NativeStart(JNIEnv*, jclass) {
    if (!g_cls) return;   // registration incomplete (logged at boot)
    // Observers and the first enumeration belong on the main queue, where
    // every later callback arrives too.
    if ([NSThread isMainThread]) Start();
    else dispatch_async(dispatch_get_main_queue(), ^{ Start(); });
}

JNINativeMethod kMethods[] = {
    {(char*)"nativeStart", (char*)"()V", (void*)NativeStart},
};

}  // namespace

// Called from native_methods.cpp::RegisterAllNativeMethods at boot.
void RegisterGamepadBridgeMethods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/loader/GamepadBridge");
    if (!cls) {
        std::fprintf(stderr, "[macapk] FindClass(GamepadBridge) failed\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return;
    }
    if (env->RegisterNatives(cls, kMethods, sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        std::fprintf(stderr, "[macapk] RegisterNatives(GamepadBridge) failed\n");
        env->ExceptionDescribe();
        env->ExceptionClear();
        env->DeleteLocalRef(cls);
        return;
    }
    g_on_connected = env->GetStaticMethodID(cls, "onConnected",
                                            "(JLjava/lang/String;IILjava/lang/String;I)I");
    g_on_disconnected = env->GetStaticMethodID(cls, "onDisconnected", "(J)V");
    g_on_state = env->GetStaticMethodID(cls, "onState", "(JIFFFFFFFF)V");
    if (!g_on_connected || !g_on_disconnected || !g_on_state) {
        std::fprintf(stderr, "[macapk] GamepadBridge callbacks missing; controllers not bridged\n");
        env->ExceptionClear();
        env->DeleteLocalRef(cls);
        return;
    }
    env->GetJavaVM(&g_vm);
    g_cls = (jclass)env->NewGlobalRef(cls);
    env->DeleteLocalRef(cls);
}

}  // namespace gamepad
}  // namespace macapk
