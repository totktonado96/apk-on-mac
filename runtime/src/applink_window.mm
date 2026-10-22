// applink_window.mm -- the Apk on Mac sign-in window: the device-browser half of
// Android App Links (see com.macapk.loader.AppLinks for the contract).
//
// An app opened a sign-in page whose redirect_uri is one of its own VERIFIED
// App Links (https, assetlinks.json-backed), or one of its own link SCHEMES
// (MACAPK_SIGNIN_WINDOW_SCHEMES: the Custom Tab that closes on return). On a device the browser hands the
// final navigation to that address to the app instead of loading it; Safari
// cannot, so the page is shown here instead. Every navigation is checked
// against the return prefix (scheme://host/path of the redirect): a match is
// cancelled, queued for the app through the same queue a LaunchServices GURL
// uses (CocoaQueueHostUrl -> HostUrlIntake), and the window closes. A link to
// any other scheme (mailto:, another app's eos.<id>:) goes to the Mac as it
// would from a browser.
//
// The cookie jar is one shared "browser" store (a fixed WKWebsiteDataStore
// identifier), not the app's WebView jar: on a device the sign-in runs in the
// browser, whose session is shared across apps and separate from any app's
// own WebView.

#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "macapk/cocoa_bridge.h"

namespace {
// Log scheme://host/path only: the query of a redirect is a one-time code.
std::string Redact(NSURL* u) {
    if (!u) return "(null)";
    NSString* s = [NSString stringWithFormat:@"%@://%@%@", u.scheme ?: @"", u.host ?: @"", u.path ?: @""];
    return [s UTF8String] ?: "";
}
}  // namespace

@interface MacapkAppLinkWindow : NSObject <WKNavigationDelegate, WKUIDelegate, NSWindowDelegate>
@property(nonatomic, strong) NSWindow* window;
@property(nonatomic, strong) WKWebView* webView;
@property(nonatomic, copy) NSString* returnPrefix;
@property(nonatomic, assign) BOOL delivered;
@end

static NSMutableSet<MacapkAppLinkWindow*>* g_open_windows = nil;   // keeps each alive while shown

@implementation MacapkAppLinkWindow

- (BOOL)isReturn:(NSURL*)url {
    if (!url) return NO;
    NSString* s = url.absoluteString;
    NSString* p = self.returnPrefix;
    if (s.length < p.length) return NO;
    if ([s compare:p options:NSCaseInsensitiveSearch range:NSMakeRange(0, p.length)] != NSOrderedSame) {
        return NO;
    }
    if (s.length == p.length) return YES;
    unichar c = [s characterAtIndex:p.length];
    return c == '?' || c == '#' || c == '/';
}

- (void)deliver:(NSURL*)url {
    if (self.delivered) return;
    self.delivered = YES;
    std::fprintf(stderr, "[applinks] sign-in window reached %s -> handed to the app\n",
                 Redact(url).c_str());
    std::fflush(stderr);
    // A browser canonicalises the scheme to lower case before it builds the
    // intent (RFC 3986 3.1; Chromium's GURL), and intent filters match schemes
    // exactly: Epic's EOS redirect comes back as eos.xyza7891U64M...://.
    NSString* s = url.absoluteString;
    NSRange colon = [s rangeOfString:@":"];
    if (colon.location != NSNotFound) {
        s = [[[s substringToIndex:colon.location] lowercaseString]
            stringByAppendingString:[s substringFromIndex:colon.location]];
    }
    macapk::CocoaQueueHostUrl([s UTF8String]);
    [self.window close];
}

- (void)webView:(WKWebView*)webView
    decidePolicyForNavigationAction:(WKNavigationAction*)action
                    decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    (void)webView;
    NSURL* url = action.request.URL;
    if ([self isReturn:url]) {
        decisionHandler(WKNavigationActionPolicyCancel);
        [self deliver:url];
        return;
    }
    NSString* scheme = url.scheme.lowercaseString ?: @"";
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"] &&
        ![scheme isEqualToString:@"about"] && ![scheme isEqualToString:@"data"] &&
        ![scheme isEqualToString:@"blob"]) {
        // A browser hands a non-web link to the OS; LaunchServices picks the app.
        decisionHandler(WKNavigationActionPolicyCancel);
        if (action.targetFrame == nil || action.targetFrame.isMainFrame) {
            [[NSWorkspace sharedWorkspace] openURL:url];
        }
        return;
    }
    decisionHandler(WKNavigationActionPolicyAllow);
}

// A server redirect straight to the return address: WebKit asks no navigation
// policy for some redirect paths, so check where the provisional load went.
- (void)webView:(WKWebView*)webView
    didReceiveServerRedirectForProvisionalNavigation:(WKNavigation*)navigation {
    (void)navigation;
    if ([self isReturn:webView.URL]) {
        NSURL* u = webView.URL;
        [webView stopLoading];
        [self deliver:u];
    }
}

// A redirect to an app link SCHEME can surface only as a failed provisional
// load ("unsupported URL") on some paths; its failing URL is the redirect.
- (void)webView:(WKWebView*)webView
    didFailProvisionalNavigation:(WKNavigation*)navigation
                       withError:(NSError*)error {
    (void)webView;
    (void)navigation;
    id failing = error.userInfo[NSURLErrorFailingURLErrorKey];
    NSURL* u = [failing isKindOfClass:[NSURL class]] ? (NSURL*)failing : nil;
    if ([self isReturn:u]) [self deliver:u];
}

- (void)webView:(WKWebView*)webView didFinishNavigation:(WKNavigation*)navigation {
    (void)navigation;
    if (webView.title.length) self.window.title = webView.title;
}

// target=_blank / window.open: keep it in this window, as a tab would.
- (WKWebView*)webView:(WKWebView*)webView
    createWebViewWithConfiguration:(WKWebViewConfiguration*)configuration
               forNavigationAction:(WKNavigationAction*)action
                    windowFeatures:(WKWindowFeatures*)features {
    (void)configuration;
    (void)features;
    if (action.request.URL) [webView loadRequest:action.request];
    return nil;
}

- (void)windowWillClose:(NSNotification*)note {
    (void)note;
    if (!self.delivered) {
        std::fprintf(stderr, "[applinks] sign-in window closed before the app's link was reached\n");
        std::fflush(stderr);
    }
    self.webView.navigationDelegate = nil;
    self.webView.UIDelegate = nil;
    MacapkAppLinkWindow* me = self;
    dispatch_async(dispatch_get_main_queue(), ^{ [g_open_windows removeObject:me]; });
}

@end

namespace macapk {

static WKWebsiteDataStore* BrowserDataStore() {
    static WKWebsiteDataStore* store = nil;
    if (store) return store;
    if (@available(macOS 14.0, *)) {
        // Fixed identifier: one browser session for every Apk on Mac app.
        NSUUID* ident = [[NSUUID alloc] initWithUUIDString:@"6D61632E-6170-6B2D-6272-6F7773657231"];
        @try {
            store = [WKWebsiteDataStore dataStoreForIdentifier:ident];
        } @catch (NSException*) {
            store = nil;
        }
    }
    if (!store) store = [WKWebsiteDataStore defaultDataStore];
    return store;
}

// The UA Safari on this Mac sends, so sign-in pages treat the window as the
// Mac's browser rather than an embedded view they might refuse.
static NSString* SafariAppName() {
    NSDictionary* info = [NSDictionary
        dictionaryWithContentsOfFile:@"/Applications/Safari.app/Contents/Info.plist"];
    NSString* v = info[@"CFBundleShortVersionString"];
    return [NSString stringWithFormat:@"Version/%@ Safari/605.1.15", v.length ? v : @"26.0"];
}

bool CocoaOpenAppLinkWindow(const char* url_c, const char* prefix_c) {
    if (!url_c || !prefix_c || !url_c[0] || !prefix_c[0]) return false;
    NSURL* url = [NSURL URLWithString:[NSString stringWithUTF8String:url_c]];
    NSString* prefix = [NSString stringWithUTF8String:prefix_c];
    if (!url || !prefix) return false;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!g_open_windows) g_open_windows = [NSMutableSet set];
        MacapkAppLinkWindow* w = [[MacapkAppLinkWindow alloc] init];
        w.returnPrefix = prefix;

        WKWebViewConfiguration* cfg = [[WKWebViewConfiguration alloc] init];
        cfg.websiteDataStore = BrowserDataStore();
        cfg.applicationNameForUserAgent = SafariAppName();

        NSRect frame = NSMakeRect(0, 0, 520, 760);
        w.window = [[NSWindow alloc]
            initWithContentRect:frame
                      styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                 NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable)
                        backing:NSBackingStoreBuffered
                          defer:NO];
        w.window.releasedWhenClosed = NO;
        w.window.title = [NSString stringWithFormat:@"Sign in - %@", url.host ?: @""];
        w.window.delegate = w;
        w.webView = [[WKWebView alloc] initWithFrame:frame configuration:cfg];
        w.webView.navigationDelegate = w;
        w.webView.UIDelegate = w;
        w.webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        w.window.contentView = w.webView;
        [w.window center];
        [g_open_windows addObject:w];
        [w.webView loadRequest:[NSURLRequest requestWithURL:url]];
        [w.window makeKeyAndOrderFront:nil];
        // The user just pressed "sign in"; a harness run asks for no activation.
        const char* na = std::getenv("MACAPK_NO_ACTIVATE");
        if (!(na && na[0] == '1')) [NSApp activateIgnoringOtherApps:YES];
        std::fprintf(stderr, "[applinks] sign-in window opened for %s, returns at %s\n",
                     Redact(url).c_str(), [prefix UTF8String]);
        std::fflush(stderr);
    });
    return true;
}

}  // namespace macapk
