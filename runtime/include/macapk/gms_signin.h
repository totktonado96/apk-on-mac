// gms_signin.h -- the Google sign-in window.
//
// ONE implementation, TWO entry points, because the alternative was two:
//   1. `macapk-runtime --gms signin-window`, which the launcher's Accounts
//      panel spawns when the user clicks "Sign in with Google".
//   2. In-app, when a guest binds the licensing service and no account exists
//      yet -- the equivalent of Android's "add an account" flow appearing at
//      the moment something needs one.
// Putting the WebView in the runtime rather than the launcher is what makes (2)
// possible at all: an installed app launched from the Dock runs this binary with
// no launcher anywhere.
//
// ⛔ THE USER TYPES THEIR PASSWORD INTO GOOGLE'S OWN PAGE, AND NOTHING HERE
// READS IT. We present a WKWebView on accounts.google.com, watch its cookie jar
// for the `oauth_token` the completed flow leaves behind, and take that one
// value. There is no form scraping, no keystroke observation, no JS injected
// into the login page, and no credential ever reaches Mac.apk. The cookie jar is
// a NON-PERSISTENT store created per sign-in, so the Google session dies with
// the window instead of lingering in a shared jar the guest could reach.
#pragma once

#include <string>

/// Present the sign-in window and block until the user finishes, cancels, or the
/// flow times out.
///
/// SAFE FROM ANY THREAD. AppKit work is marshalled onto the main queue and the
/// caller waits, which is the same one-directional pattern webview_bridge.mm
/// documents: a guest thread may park waiting on the main thread, the main
/// thread never waits on a guest thread, so there is no cycle. Calling it ON the
/// main thread would deadlock, so that case runs the flow inline instead.
///
/// @return the raw `oauth_token` value, or an empty string when the user
///         cancelled or the flow failed. An empty string is never an error to
///         report as such -- the caller distinguishes cancel from failure by
///         asking whether anything was signed in afterwards.
std::string MacApkPresentGoogleSignIn();

/// True while a sign-in window is on screen. The in-app path uses this so a
/// second licence check cannot stack a second window on top of the first.
bool MacApkGoogleSignInActive();
