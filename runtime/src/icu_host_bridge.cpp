// icu_host_bridge.cpp -- com.macapk.icu.HostIcu's natives: ICU number-skeleton
// formatting through the host's own ICU4C, /usr/lib/libicucore.A.dylib.
//
// WHY. android.icu.text.MeasureFormat (Hermes' Intl.NumberFormat {style:"unit"})
// needs CLDR unit patterns, which the JDK does not ship. macOS does: libicucore
// is ICU4C (78.1 on macOS 26) and exports its C API, so this is decision-ladder
// rung 1 -- the host supports it natively. The functions are resolved with
// dlsym at first use (no link-time dependency on a private Apple library, and a
// missing symbol degrades to an IllegalStateException instead of a dyld abort).
//
// C API used (unicode/unumberformatter.h, ICU 62+; unicode/utypes.h):
//   UNumberFormatter* unumf_openForSkeletonAndLocale(const UChar* skeleton,
//       int32_t skeletonLen, const char* locale, UErrorCode* ec);
//   UFormattedNumber* unumf_openResult(UErrorCode* ec);
//   void unumf_formatDouble(const UNumberFormatter*, double, UFormattedNumber*, UErrorCode*);
//   void unumf_formatDecimal(const UNumberFormatter*, const char* value, int32_t valueLen,
//       UFormattedNumber*, UErrorCode*);
//   int32_t unumf_resultToString(const UFormattedNumber*, UChar* buffer, int32_t cap, UErrorCode*);
//   void unumf_close(UNumberFormatter*);  void unumf_closeResult(UFormattedNumber*);
//   const char* u_errorName(UErrorCode);
// UErrorCode is an int32 enum: > 0 (U_ZERO_ERROR = 0) is a failure, < 0 a warning
// (U_USING_FALLBACK_WARNING -128, U_USING_DEFAULT_WARNING -127 are normal here).
// UChar is char16_t, which is jchar's representation.
//
// Also android.icu.util.LocaleData (GitHub #14: MapLibre Compose picks map units
// with LocaleData.getMeasurementSystem and died on NoClassDefFoundError). The
// answers live in CLDR supplemental data plus likely-subtags region inference,
// neither of which the JDK exposes; ICU4C's ulocdata API is the C twin of the
// ICU4J class Android ships, over the same data (unicode/ulocdata.h, uset.h):
//   UMeasurementSystem ulocdata_getMeasurementSystem(const char* localeID, UErrorCode*);
//       UMS_SI 0, UMS_US 1, UMS_UK 2 (ICU4J's switch uses the same numbers)
//   void ulocdata_getPaperSize(const char* localeID, int32_t* h, int32_t* w, UErrorCode*);
//   void ulocdata_getCLDRVersion(UVersionInfo versionArray, UErrorCode*);  // uint8_t[4]
//   ULocaleData* ulocdata_open(const char* localeID, UErrorCode*);  void ulocdata_close(ULocaleData*);
//   void ulocdata_setNoSubstitute(ULocaleData*, UBool);
//   USet* ulocdata_getExemplarSet(ULocaleData*, USet* fillIn, uint32_t options,
//       ULocaleDataExemplarSetType extype, UErrorCode*);
//       C extype: STANDARD 0, AUXILIARY 1, INDEX 2, PUNCTUATION 3 (ICU4J: PUNCTUATION 4,
//       because Java keeps the retired ES_CURRENCY at 3; the Java side maps it)
//   int32_t ulocdata_getDelimiter(ULocaleData*, ULocaleDataDelimiterType, UChar* out, int32_t cap, UErrorCode*);
//   int32_t ulocdata_getLocaleDisplayPattern(ULocaleData*, UChar* out, int32_t cap, UErrorCode*);
//   int32_t ulocdata_getLocaleSeparator(ULocaleData*, UChar* out, int32_t cap, UErrorCode*);
//   int32_t uset_getItemCount(const USet*);  void uset_close(USet*);
//   int32_t uset_getItem(const USet*, int32_t i, UChar32* start, UChar32* end,
//       UChar* str, int32_t strCapacity, UErrorCode*);  // 0 = range, else string length
// With noSubstitute set, ICU4C turns "only root had it" into U_MISSING_RESOURCE_ERROR,
// which is ICU4J's null.
#include <jni.h>

#include <dlfcn.h>

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

namespace {

using UErrorCode = int32_t;
using UNumberFormatter = void;
using UFormattedNumber = void;

struct IcuApi {
    UNumberFormatter* (*openForSkeletonAndLocale)(const char16_t*, int32_t, const char*, UErrorCode*) = nullptr;
    UFormattedNumber* (*openResult)(UErrorCode*) = nullptr;
    void (*formatDouble)(const UNumberFormatter*, double, UFormattedNumber*, UErrorCode*) = nullptr;
    void (*formatDecimal)(const UNumberFormatter*, const char*, int32_t, UFormattedNumber*, UErrorCode*) = nullptr;
    int32_t (*resultToString)(const UFormattedNumber*, char16_t*, int32_t, UErrorCode*) = nullptr;
    void (*close)(UNumberFormatter*) = nullptr;
    void (*closeResult)(UFormattedNumber*) = nullptr;
    const char* (*errorName)(UErrorCode) = nullptr;
    bool ok = false;
};

const IcuApi& Api() {
    static IcuApi api;
    static std::once_flag once;
    std::call_once(once, [] {
        void* h = dlopen("/usr/lib/libicucore.A.dylib", RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            std::fprintf(stderr, "[E] icu-host: dlopen(libicucore) failed: %s\n", dlerror());
            return;
        }
#define MACAPK_ICU_SYM(field, name) api.field = reinterpret_cast<decltype(api.field)>(dlsym(h, name))
        MACAPK_ICU_SYM(openForSkeletonAndLocale, "unumf_openForSkeletonAndLocale");
        MACAPK_ICU_SYM(openResult, "unumf_openResult");
        MACAPK_ICU_SYM(formatDouble, "unumf_formatDouble");
        MACAPK_ICU_SYM(formatDecimal, "unumf_formatDecimal");
        MACAPK_ICU_SYM(resultToString, "unumf_resultToString");
        MACAPK_ICU_SYM(close, "unumf_close");
        MACAPK_ICU_SYM(closeResult, "unumf_closeResult");
        MACAPK_ICU_SYM(errorName, "u_errorName");
#undef MACAPK_ICU_SYM
        api.ok = api.openForSkeletonAndLocale && api.openResult && api.formatDouble &&
                 api.formatDecimal && api.resultToString && api.close && api.closeResult &&
                 api.errorName;
        if (!api.ok) std::fprintf(stderr, "[E] icu-host: libicucore lacks the unumf_* API\n");
    });
    return api;
}

void Throw(JNIEnv* env, const char* cls, const std::string& msg) {
    jclass c = env->FindClass(cls);
    if (c) env->ThrowNew(c, msg.c_str());
}

std::string Utf8(JNIEnv* env, jstring s) {
    if (!s) return std::string();
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return out;
}

// One format call: skeleton + locale -> formatter, value -> string. Either a
// double or a decimal string (`dec` non-null) is formatted.
jstring Format(JNIEnv* env, jstring jskeleton, jstring jlocale, double value, const std::string* dec) {
    const IcuApi& api = Api();
    if (!api.ok) {
        Throw(env, "java/lang/IllegalStateException", "host ICU (libicucore unumf_*) unavailable");
        return nullptr;
    }
    if (!jskeleton) {
        Throw(env, "java/lang/NullPointerException", "skeleton");
        return nullptr;
    }
    const jsize n = env->GetStringLength(jskeleton);
    std::vector<char16_t> sk(static_cast<size_t>(n) + 1);
    env->GetStringRegion(jskeleton, 0, n, reinterpret_cast<jchar*>(sk.data()));
    const std::string locale = Utf8(env, jlocale);

    UErrorCode ec = 0;
    UNumberFormatter* f = api.openForSkeletonAndLocale(sk.data(), n, locale.c_str(), &ec);
    if (ec > 0 || !f) {
        if (f) api.close(f);
        Throw(env, "java/lang/IllegalArgumentException",
              std::string("unumf_openForSkeletonAndLocale: ") + api.errorName(ec));
        return nullptr;
    }
    UFormattedNumber* r = api.openResult(&ec);
    if (ec > 0 || !r) {
        api.close(f);
        if (r) api.closeResult(r);
        Throw(env, "java/lang/IllegalStateException", std::string("unumf_openResult: ") + api.errorName(ec));
        return nullptr;
    }
    if (dec) api.formatDecimal(f, dec->c_str(), static_cast<int32_t>(dec->size()), r, &ec);
    else api.formatDouble(f, value, r, &ec);
    jstring out = nullptr;
    if (ec <= 0) {
        char16_t buf[256];
        UErrorCode ec2 = 0;
        int32_t len = api.resultToString(r, buf, 256, &ec2);
        if (ec2 <= 0 && len >= 0 && len <= 256) {
            out = env->NewString(reinterpret_cast<const jchar*>(buf), len);
        } else if (len > 256) {      // U_BUFFER_OVERFLOW_ERROR: retry at the reported size
            std::vector<char16_t> big(static_cast<size_t>(len) + 1);
            ec2 = 0;
            len = api.resultToString(r, big.data(), len + 1, &ec2);
            if (ec2 <= 0) out = env->NewString(reinterpret_cast<const jchar*>(big.data()), len);
        }
        if (!out && !env->ExceptionCheck()) {
            Throw(env, "java/lang/IllegalStateException",
                  std::string("unumf_resultToString: ") + api.errorName(ec2));
        }
    } else {
        Throw(env, "java/lang/IllegalArgumentException", std::string("unumf_format: ") + api.errorName(ec));
    }
    api.closeResult(r);
    api.close(f);
    return out;
}

jstring JNICALL NativeFormatDouble(JNIEnv* env, jclass, jstring sk, jstring loc, jdouble v) {
    return Format(env, sk, loc, v, nullptr);
}

jstring JNICALL NativeFormatDecimal(JNIEnv* env, jclass, jstring sk, jstring loc, jstring dec) {
    if (!dec) {
        Throw(env, "java/lang/NullPointerException", "decimal");
        return nullptr;
    }
    const std::string d = Utf8(env, dec);
    return Format(env, sk, loc, 0.0, &d);
}

// ---- android.icu.util.LocaleData ------------------------------------------

using ULocaleData = void;
using USet = void;

struct LocaleDataApi {
    int32_t (*measurementSystem)(const char*, UErrorCode*) = nullptr;
    void (*paperSize)(const char*, int32_t*, int32_t*, UErrorCode*) = nullptr;
    void (*cldrVersion)(uint8_t*, UErrorCode*) = nullptr;
    ULocaleData* (*open)(const char*, UErrorCode*) = nullptr;
    void (*close)(ULocaleData*) = nullptr;
    void (*setNoSubstitute)(ULocaleData*, int8_t) = nullptr;   // UBool is int8_t
    USet* (*exemplarSet)(ULocaleData*, USet*, uint32_t, int32_t, UErrorCode*) = nullptr;
    int32_t (*delimiter)(ULocaleData*, int32_t, char16_t*, int32_t, UErrorCode*) = nullptr;
    int32_t (*displayPattern)(ULocaleData*, char16_t*, int32_t, UErrorCode*) = nullptr;
    int32_t (*separator)(ULocaleData*, char16_t*, int32_t, UErrorCode*) = nullptr;
    int32_t (*setItemCount)(const USet*) = nullptr;
    int32_t (*setItem)(const USet*, int32_t, int32_t*, int32_t*, char16_t*, int32_t, UErrorCode*) = nullptr;
    void (*setClose)(USet*) = nullptr;
    const char* (*errorName)(UErrorCode) = nullptr;
    bool ok = false;
};

// Separate from Api() so a host ICU missing one family never disables the other.
const LocaleDataApi& LdApi() {
    static LocaleDataApi api;
    static std::once_flag once;
    std::call_once(once, [] {
        void* h = dlopen("/usr/lib/libicucore.A.dylib", RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            std::fprintf(stderr, "[E] icu-host: dlopen(libicucore) failed: %s\n", dlerror());
            return;
        }
#define MACAPK_ICU_SYM(field, name) api.field = reinterpret_cast<decltype(api.field)>(dlsym(h, name))
        MACAPK_ICU_SYM(measurementSystem, "ulocdata_getMeasurementSystem");
        MACAPK_ICU_SYM(paperSize, "ulocdata_getPaperSize");
        MACAPK_ICU_SYM(cldrVersion, "ulocdata_getCLDRVersion");
        MACAPK_ICU_SYM(open, "ulocdata_open");
        MACAPK_ICU_SYM(close, "ulocdata_close");
        MACAPK_ICU_SYM(setNoSubstitute, "ulocdata_setNoSubstitute");
        MACAPK_ICU_SYM(exemplarSet, "ulocdata_getExemplarSet");
        MACAPK_ICU_SYM(delimiter, "ulocdata_getDelimiter");
        MACAPK_ICU_SYM(displayPattern, "ulocdata_getLocaleDisplayPattern");
        MACAPK_ICU_SYM(separator, "ulocdata_getLocaleSeparator");
        MACAPK_ICU_SYM(setItemCount, "uset_getItemCount");
        MACAPK_ICU_SYM(setItem, "uset_getItem");
        MACAPK_ICU_SYM(setClose, "uset_close");
        MACAPK_ICU_SYM(errorName, "u_errorName");
#undef MACAPK_ICU_SYM
        api.ok = api.measurementSystem && api.paperSize && api.cldrVersion && api.open &&
                 api.close && api.setNoSubstitute && api.exemplarSet && api.delimiter &&
                 api.displayPattern && api.separator && api.setItemCount && api.setItem &&
                 api.setClose && api.errorName;
        if (!api.ok) std::fprintf(stderr, "[E] icu-host: libicucore lacks the ulocdata_* API\n");
    });
    return api;
}

// ICU4C reads "" as "the default locale"; ICU4J's ROOT (getName() == "") is the
// root locale. "und" is the ID that behaves like ICU4J's ROOT in both families:
// resource lookups fall back to root, and region inference runs likely subtags
// (und -> en_Latn_US), where ICU4C's "root" infers no region and lands on 001.
std::string LocaleId(JNIEnv* env, jstring jlocale) {
    std::string id = Utf8(env, jlocale);
    return id.empty() ? std::string("und") : id;
}

const LocaleDataApi* LdApiOrThrow(JNIEnv* env) {
    const LocaleDataApi& api = LdApi();
    if (!api.ok) {
        Throw(env, "java/lang/IllegalStateException", "host ICU (libicucore ulocdata_*) unavailable");
        return nullptr;
    }
    return &api;
}

// An ICU failure on a supplemental lookup is MissingResourceException in ICU4J.
void ThrowMissing(JNIEnv* env, const LocaleDataApi& api, const char* what, UErrorCode ec) {
    Throw(env, "java/util/MissingResourceException", std::string(what) + ": " + api.errorName(ec));
}

jint JNICALL NativeMeasurementSystem(JNIEnv* env, jclass, jstring loc) {
    const LocaleDataApi* api = LdApiOrThrow(env);
    if (!api) return -1;
    const std::string id = LocaleId(env, loc);
    UErrorCode ec = 0;
    int32_t ms = api->measurementSystem(id.c_str(), &ec);
    if (ec > 0) {
        ThrowMissing(env, *api, "ulocdata_getMeasurementSystem", ec);
        return -1;
    }
    return ms;
}

jintArray JNICALL NativePaperSize(JNIEnv* env, jclass, jstring loc) {
    const LocaleDataApi* api = LdApiOrThrow(env);
    if (!api) return nullptr;
    const std::string id = LocaleId(env, loc);
    UErrorCode ec = 0;
    int32_t hw[2] = {0, 0};
    api->paperSize(id.c_str(), &hw[0], &hw[1], &ec);
    if (ec > 0) {
        ThrowMissing(env, *api, "ulocdata_getPaperSize", ec);
        return nullptr;
    }
    jintArray out = env->NewIntArray(2);
    if (out) env->SetIntArrayRegion(out, 0, 2, hw);
    return out;
}

jintArray JNICALL NativeCldrVersion(JNIEnv* env, jclass) {
    const LocaleDataApi* api = LdApiOrThrow(env);
    if (!api) return nullptr;
    uint8_t v[4] = {0, 0, 0, 0};
    UErrorCode ec = 0;
    api->cldrVersion(v, &ec);
    if (ec > 0) {
        ThrowMissing(env, *api, "ulocdata_getCLDRVersion", ec);
        return nullptr;
    }
    const jint vi[4] = {v[0], v[1], v[2], v[3]};
    jintArray out = env->NewIntArray(4);
    if (out) env->SetIntArrayRegion(out, 0, 4, vi);
    return out;
}

// One ULocaleData for the duration of a call; closed on every path.
struct LdHandle {
    const LocaleDataApi& api;
    ULocaleData* uld = nullptr;
    LdHandle(const LocaleDataApi& a, const std::string& id, bool noSubstitute, UErrorCode* ec) : api(a) {
        uld = api.open(id.c_str(), ec);
        if (uld) api.setNoSubstitute(uld, noSubstitute ? 1 : 0);
    }
    ~LdHandle() { if (uld) api.close(uld); }
};

// Reads one UChar string through `get` (delimiter / display pattern / separator),
// growing the buffer once on U_BUFFER_OVERFLOW_ERROR. Returns null with ec > 0 left
// for the caller to interpret.
template <typename Get>
jstring ReadUString(JNIEnv* env, Get get, UErrorCode* ec) {
    char16_t buf[64];
    int32_t len = get(buf, 64, ec);
    if (*ec == 15 /* U_BUFFER_OVERFLOW_ERROR */ && len > 64) {
        std::vector<char16_t> big(static_cast<size_t>(len) + 1);
        *ec = 0;
        len = get(big.data(), len + 1, ec);
        if (*ec > 0) return nullptr;
        return env->NewString(reinterpret_cast<const jchar*>(big.data()), len);
    }
    if (*ec > 0 || len < 0) return nullptr;
    return env->NewString(reinterpret_cast<const jchar*>(buf), len < 64 ? len : 64);
}

// null when the locale (or, under noSubstitute, the non-root data) has no such delimiter.
jstring JNICALL NativeDelimiter(JNIEnv* env, jclass, jstring loc, jboolean noSubstitute, jint type) {
    const LocaleDataApi* api = LdApiOrThrow(env);
    if (!api) return nullptr;
    UErrorCode ec = 0;
    LdHandle h(*api, LocaleId(env, loc), noSubstitute, &ec);
    if (!h.uld || ec > 0) return nullptr;
    return ReadUString(env, [&](char16_t* b, int32_t cap, UErrorCode* e) {
        return api->delimiter(h.uld, type, b, cap, e);
    }, &ec);
}

// {int[] ranges as start,end pairs, String[] strings}, or null when ICU has no set.
jobjectArray JNICALL NativeExemplarSet(JNIEnv* env, jclass, jstring loc, jboolean noSubstitute,
                                       jint options, jint cExtype) {
    const LocaleDataApi* api = LdApiOrThrow(env);
    if (!api) return nullptr;
    UErrorCode ec = 0;
    LdHandle h(*api, LocaleId(env, loc), noSubstitute, &ec);
    if (!h.uld || ec > 0) return nullptr;
    USet* set = api->exemplarSet(h.uld, nullptr, static_cast<uint32_t>(options), cExtype, &ec);
    if (!set) return nullptr;
    if (ec > 0) {
        api->setClose(set);
        return nullptr;
    }
    std::vector<jint> ranges;
    std::vector<std::u16string> strs;
    const int32_t n = api->setItemCount(set);
    for (int32_t i = 0; i < n; i++) {
        int32_t start = 0, end = 0;
        char16_t sbuf[128];
        UErrorCode e2 = 0;
        int32_t slen = api->setItem(set, i, &start, &end, sbuf, 128, &e2);
        if (e2 > 0) continue;
        if (slen == 0) {
            ranges.push_back(start);
            ranges.push_back(end);
        } else {
            strs.emplace_back(sbuf, static_cast<size_t>(slen < 128 ? slen : 128));
        }
    }
    api->setClose(set);

    jclass objCls = env->FindClass("java/lang/Object");
    jclass strCls = env->FindClass("java/lang/String");
    if (!objCls || !strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(2, objCls, nullptr);
    jintArray jr = env->NewIntArray(static_cast<jsize>(ranges.size()));
    jobjectArray js = env->NewObjectArray(static_cast<jsize>(strs.size()), strCls, nullptr);
    if (!out || !jr || !js) return nullptr;
    if (!ranges.empty()) env->SetIntArrayRegion(jr, 0, static_cast<jsize>(ranges.size()), ranges.data());
    for (size_t i = 0; i < strs.size(); i++) {
        jstring s = env->NewString(reinterpret_cast<const jchar*>(strs[i].data()),
                                   static_cast<jsize>(strs[i].size()));
        env->SetObjectArrayElement(js, static_cast<jsize>(i), s);
        env->DeleteLocalRef(s);
    }
    env->SetObjectArrayElement(out, 0, jr);
    env->SetObjectArrayElement(out, 1, js);
    return out;
}

// ICU4J reads these from the lang bundle with no noSubstitute check and throws
// MissingResourceException when absent; open without noSubstitute to match.
jstring LocaleDisplayString(JNIEnv* env, jstring loc, bool separator) {
    const LocaleDataApi* api = LdApiOrThrow(env);
    if (!api) return nullptr;
    UErrorCode ec = 0;
    LdHandle h(*api, LocaleId(env, loc), false, &ec);
    jstring out = nullptr;
    if (h.uld && ec <= 0) {
        out = ReadUString(env, [&](char16_t* b, int32_t cap, UErrorCode* e) {
            return separator ? api->separator(h.uld, b, cap, e) : api->displayPattern(h.uld, b, cap, e);
        }, &ec);
    }
    if (!out && !env->ExceptionCheck()) {
        ThrowMissing(env, *api, separator ? "ulocdata_getLocaleSeparator"
                                          : "ulocdata_getLocaleDisplayPattern", ec);
    }
    return out;
}

jstring JNICALL NativeLocaleDisplayPattern(JNIEnv* env, jclass, jstring loc) {
    return LocaleDisplayString(env, loc, false);
}

jstring JNICALL NativeLocaleSeparator(JNIEnv* env, jclass, jstring loc) {
    return LocaleDisplayString(env, loc, true);
}

// Every native HostIcu declares, with its exact descriptor: RegisterNatives
// fails the WHOLE table on one mismatch.
const JNINativeMethod kIcuHostMethods[] = {
    {const_cast<char*>("nativeFormatDouble"),
     const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;D)Ljava/lang/String;"),
     reinterpret_cast<void*>(NativeFormatDouble)},
    {const_cast<char*>("nativeFormatDecimal"),
     const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
     reinterpret_cast<void*>(NativeFormatDecimal)},
    {const_cast<char*>("nativeMeasurementSystem"), const_cast<char*>("(Ljava/lang/String;)I"),
     reinterpret_cast<void*>(NativeMeasurementSystem)},
    {const_cast<char*>("nativePaperSize"), const_cast<char*>("(Ljava/lang/String;)[I"),
     reinterpret_cast<void*>(NativePaperSize)},
    {const_cast<char*>("nativeCldrVersion"), const_cast<char*>("()[I"),
     reinterpret_cast<void*>(NativeCldrVersion)},
    {const_cast<char*>("nativeDelimiter"), const_cast<char*>("(Ljava/lang/String;ZI)Ljava/lang/String;"),
     reinterpret_cast<void*>(NativeDelimiter)},
    {const_cast<char*>("nativeExemplarSet"),
     const_cast<char*>("(Ljava/lang/String;ZII)[Ljava/lang/Object;"),
     reinterpret_cast<void*>(NativeExemplarSet)},
    {const_cast<char*>("nativeLocaleDisplayPattern"), const_cast<char*>("(Ljava/lang/String;)Ljava/lang/String;"),
     reinterpret_cast<void*>(NativeLocaleDisplayPattern)},
    {const_cast<char*>("nativeLocaleSeparator"), const_cast<char*>("(Ljava/lang/String;)Ljava/lang/String;"),
     reinterpret_cast<void*>(NativeLocaleSeparator)},
};

}  // namespace

namespace macapk {
namespace icuhost {

// Registers com.macapk.icu.HostIcu's natives. SOFT-FAILS like the clipboard
// registration: a miss leaves HostIcu.formatSkeleton throwing
// UnsupportedOperationException (unit formatting unavailable); never aborts boot.
// Returns true when registered.
bool RegisterIcuHostMethods(JNIEnv* env) {
    jclass cls = env->FindClass("com/macapk/icu/HostIcu");
    if (!cls) {
        std::fprintf(stderr, "[E] icu-host: FindClass(com.macapk.icu.HostIcu) failed\n");
        env->ExceptionClear();
        return false;
    }
    bool ok = env->RegisterNatives(cls, kIcuHostMethods,
                                   sizeof(kIcuHostMethods) / sizeof(kIcuHostMethods[0])) == JNI_OK;
    if (!ok) {
        std::fprintf(stderr, "[E] icu-host: RegisterNatives(HostIcu) failed\n");
        env->ExceptionClear();
    }
    env->DeleteLocalRef(cls);
    return ok;
}

}  // namespace icuhost
}  // namespace macapk

#ifdef MACAPK_ICU_HOST_STANDALONE
// Offline gate build (debug/icuintl_gate.sh): the same file compiled as a
// System.load()-able dylib, so the bare-JVM harness exercises these exact
// natives without the runtime.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8) != JNI_OK) return JNI_ERR;
    return macapk::icuhost::RegisterIcuHostMethods(env) ? JNI_VERSION_1_8 : JNI_ERR;
}
#endif
