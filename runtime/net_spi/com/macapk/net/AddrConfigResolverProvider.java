// AddrConfigResolverProvider -- give guests the AI_ADDRCONFIG name-resolution
// semantics that AOSP gives them, instead of stock OpenJDK's.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS (the divergence, both sides cited)
// ---------------------------------------------------------------------------
// Android's libcore passes AI_ADDRCONFIG to getaddrinfo. Stock OpenJDK does
// not. That one flag decides whether an app is handed addresses of a family
// the device cannot actually route.
//
// AOSP, platform/libcore
// ojluni/src/main/java/java/net/Inet6AddressImpl.java:128-135
// (android.googlesource.com/platform/libcore, android11-release; verified
// 2026-08-12 -- note libcore is NOT on the aosp-mirror GitHub org, it must be
// fetched from googlesource with ?format=TEXT and base64-decoded):
//
//     StructAddrinfo hints = new StructAddrinfo();
//     hints.ai_flags = AI_ADDRCONFIG;
//     hints.ai_family = AF_UNSPEC;
//     hints.ai_socktype = SOCK_STREAM;
//     InetAddress[] addresses = Libcore.os.android_getaddrinfo(host, hints, netId);
//
// Bionic, bionic/libc/dns/net/getaddrinfo.c:1935 -- what the flag actually
// does. Without it both families are queried unconditionally; with it, each
// family is queried only if the device can reach that family:
//
//     if (pai->ai_flags & AI_ADDRCONFIG) {
//             query_ipv6 = _have_ipv6(netcontext->app_mark, netcontext->uid);
//             query_ipv4 = _have_ipv4(netcontext->app_mark, netcontext->uid);
//     }
//
// and the probes themselves (same file), which are the behaviour this class
// reimplements:
//
//     static int _have_ipv6(unsigned mark, uid_t uid) {
//         static const struct sockaddr_in6 sin6_test = {
//             .sin6_family = AF_INET6,
//             .sin6_addr.s6_addr = {  // 2000::
//                 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };
//         sockaddr_union addr = { .in6 = sin6_test };
//         return _find_src_addr(&addr.generic, NULL, mark, uid) == 1;
//     }
//     static int _have_ipv4(unsigned mark, uid_t uid) {
//         static const struct sockaddr_in sin_test = {
//             .sin_family = AF_INET,
//             .sin_addr.s_addr = __constant_htonl(0x08080808L)  // 8.8.8.8
//         };
//         ...
//     }
//
// _find_src_addr is a UDP socket + connect() + getsockname(). A UDP connect
// puts NO packets on the wire -- it is a pure kernel route lookup -- which is
// why Bionic can afford to do this on every resolution.
//
// OpenJDK 21, src/java.base/unix/native/libnet/Inet6AddressImpl.c,
// Java_java_net_Inet6AddressImpl_lookupAllHostAddr:
//
//     memset(&hints, 0, sizeof(hints));
//     hints.ai_flags = AI_CANONNAME;
//     hints.ai_family = lookupCharacteristicsToAddressFamily(characteristics);
//
// No AI_ADDRCONFIG. That is long-standing, deliberate OpenJDK behaviour and not
// a bug we introduced -- but it is not Android's behaviour, and guest apps are
// written against Android's.
//
// ---------------------------------------------------------------------------
// WHAT IT COST US (measured on this host, 2026-08-12, macOS 26.5.2)
// ---------------------------------------------------------------------------
// Host has no global IPv6 route (`route -n get -inet6 default` ->
// "not in table"; no inet6 address outside fd00::/8 ULA autoconf).
//
//   C getaddrinfo("auroraoss.com")            -> 2 addresses, both IPv4
//   Java InetAddress.getAllByName(same)       -> 4: 2 IPv4 then 2 IPv6
//
//   CONNECT OK   IPv4 104.21.75.61                    (10 ms)
//   CONNECT OK   IPv4 172.67.215.30                   ( 7 ms)
//   CONNECT FAIL IPv6 2606:4700:3032::ac43:d71e  -> NoRouteToHostException (0 ms)
//   CONNECT FAIL IPv6 2606:4700:3034::6815:4b3d  -> NoRouteToHostException (0 ms)
//
// Reproduced for play.google.com and accounts.google.com. The exception string
// "No route to host" is strerror(EHOSTUNREACH) from the host kernel; no Apk on Mac
// code produces it (`grep -rn "No route to host" runtime/` -> no hits).
//
// This is worth fixing even though most HTTP clients iterate the address list,
// for two reasons:
//   1. OkHttp 5 enables Happy Eyeballs by default and tries IPv6 FIRST, so the
//      unroutable family is on the hot path of every request, not the fallback.
//   2. When a client does exhaust every route it reports firstException -- the
//      IPv6 NoRouteToHostException -- so a failure whose real cause was on the
//      IPv4 leg gets RENAMED to "No route to host" in front of the user. The
//      defect is an active diagnostic corrupter, not just a latency cost.
//
// ---------------------------------------------------------------------------
// WHY A ServiceLoader PROVIDER, AND WHY IT COMPILES SEPARATELY
// ---------------------------------------------------------------------------
// java.net.spi.InetAddressResolverProvider is the ONLY supported interception
// point: guests call java.net.InetAddress.getAllByName directly, and java.* may
// not be shadowed from the app classpath (ClassLoader.preDefineClass rejects it
// with "Prohibited package name"). The alternatives were considered and are
// worse: --patch-module java.base would mean carrying a whole copy of a
// version-coupled internal class, and -Djava.net.preferIPv4Stack=true is not
// AOSP-faithful -- it disables IPv6 unconditionally, including on a host that
// HAS a route, and it hides IPv6 from NetworkInterface enumeration too. That
// property was REMOVED from jvm_loader.cpp for exactly those reasons
// (jvm_loader.cpp:139-152); this class is the replacement that was never
// written at the time, and it is ADAPTIVE where the property was absolute.
//
// The SPI is JDK 18+, and runtime/scripts/build.sh compiles the framework with
// --release 21, so this file cannot go in runtime/java/ -- the main javac pass
// would fail on it. It lives in runtime/net_spi/ and gets its own javac pass at
// the platform's own level, exactly like runtime/java_base_patch/ and
// runtime/jdk_unsupported_patch/ already do. Output lands in
// runtime/build/classes/com/macapk/net/, which puts it in macapk-loader.jar --
// Apk on Mac infrastructure, not Android API surface.
//
// It ALSO lands in android-framework.jar, and that is worth knowing rather than
// being surprised by later. build.sh's framework file list reads
//
//     find . -type f -name '*.class' \( -path './com/macapk/*' -prune -false -o -print \)
//
// which LOOKS like it excludes com/macapk but does not: -prune only suppresses
// descent into a DIRECTORY, and -type f has already filtered directories out, so
// the left branch is a no-op that falls through to -print. MEASURED 2026-08-12:
// android-framework.jar carries all 193 com/macapk classes, and always has. That
// is a pre-existing build wart, NOT something this file introduced, and it is
// harmless here -- the class simply resolves from whichever jar comes first on
// the classpath, and the META-INF/services entry that actually activates it is
// added to macapk-loader.jar only. Do not "fix" the prune casually: it would
// change android-framework.jar's contents and therefore FRAMEWORK_ID for
// everyone.
//
// ---------------------------------------------------------------------------
// HOW IT IS FOUND AT RUNTIME
// ---------------------------------------------------------------------------
// InetAddress.loadResolver() (JDK 21 InetAddress.java:506) does
//
//     ServiceLoader.load(InetAddressResolverProvider.class).findFirst()...
//
// -- the ONE-ARG form, which uses the THREAD CONTEXT class loader
// (ServiceLoader.java:1696-1699), not the system loader. On a guest thread the
// TCCL is the AppClassLoader that Boot installs (Boot.java:469/872/1349), whose
// parent is Boot.class.getClassLoader() = the system loader (Boot.java:466), and
// whose loadClass/getResources are parent-first. macapk-loader.jar is on the
// system classpath (main.cpp:1893). So the provider resolves from any guest
// thread and from the main thread alike.
//
// Two JDK behaviours this relies on, both read from InetAddress.java:459-502:
//   * The resolver is looked up ONCE, lazily, on the first name resolution, and
//     cached in a static. There is no ordering requirement against Boot.
//   * A provider is skipped entirely when jdk.net.hosts.file is set. Apk on Mac
//     sets that for MACAPK_OFFLINE=1 (jvm_loader.cpp), so offline mode keeps
//     working unchanged and this class simply never loads.
//
// ---------------------------------------------------------------------------
// GATE
// ---------------------------------------------------------------------------
// Default ON (AOSP-faithful). MACAPK_ADDRCONFIG=0 disables the filtering and
// makes every lookup pass through untouched, for A/B without a rebuild.
//
// NOT app-specific: there is no package name, no per-APK branch, and no app can
// observe anything except the address list a real device would have given it.

package com.macapk.net;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public final class AddrConfigResolverProvider extends InetAddressResolverProvider {

    /** MACAPK_ADDRCONFIG=0 -> pass every lookup through unfiltered. */
    private static final boolean ENABLED =
        !("0".equals(System.getenv("MACAPK_ADDRCONFIG"))
          || "false".equalsIgnoreCase(System.getenv("MACAPK_ADDRCONFIG")));

    @Override
    public InetAddressResolver get(Configuration configuration) {
        // MUST NOT throw. Anything escaping get() surfaces as a
        // ServiceConfigurationError out of InetAddress.loadResolver, which
        // would break DNS for every app in the process rather than just
        // disabling this feature.
        try {
            InetAddressResolver builtin = configuration.builtinResolver();
            if (!ENABLED) return builtin;
            return new AddrConfigResolver(builtin);
        } catch (Throwable t) {
            System.err.println("[W] Apk on Mac.addrconfig: provider init failed, "
                + "using builtin resolver: " + t);
            try {
                return configuration.builtinResolver();
            } catch (Throwable t2) {
                // Cannot recover; rethrowing here is no worse than returning
                // null, and null would NPE inside InetAddress instead.
                throw t2;
            }
        }
    }

    @Override
    public String name() {
        return "macapk-addrconfig";
    }

    // -----------------------------------------------------------------------

    private static final class AddrConfigResolver implements InetAddressResolver {

        private final InetAddressResolver builtin;

        AddrConfigResolver(InetAddressResolver builtin) {
            this.builtin = builtin;
        }

        @Override
        public Stream<InetAddress> lookupByName(String host, LookupPolicy policy)
                throws UnknownHostException {
            Stream<InetAddress> raw = builtin.lookupByName(host, policy);
            if (!ENABLED) return raw;

            // Reentrancy guard. The route probe below opens a DatagramChannel;
            // if anything on that path ever performed a name lookup we would
            // recurse into ourselves forever. The JDK's own bootstrapResolver
            // guard (InetAddress.java:476-479) only covers provider
            // INITIALISATION, not steady-state lookups, so we need our own.
            if (Probe.inProbe()) return raw;

            List<InetAddress> all = raw.toList();
            if (all.size() < 2) return all.stream();   // nothing to choose between

            boolean have6 = Probe.haveIpv6();
            boolean have4 = Probe.haveIpv4();
            if (have6 && have4) return all.stream();   // dual stack: AOSP filters nothing

            List<InetAddress> kept = new ArrayList<>(all.size());
            for (InetAddress a : all) {
                if (isAlwaysKept(a)) { kept.add(a); continue; }
                boolean v6 = (a instanceof Inet6Address);
                if (v6 ? have6 : have4) kept.add(a);
            }

            // Never filter to empty. If a host publishes ONLY records of a
            // family we cannot route, hand the app the unfiltered list and let
            // it produce its own connect error -- that is strictly more
            // informative than UnknownHostException, and it keeps a wrong probe
            // from turning a reachable host into a nonexistent one.
            if (kept.isEmpty()) return all.stream();

            if (kept.size() != all.size()) Probe.noteFiltered(host, all.size(), kept.size());
            return kept.stream();
        }

        @Override
        public String lookupByAddress(byte[] addr) throws UnknownHostException {
            return builtin.lookupByAddress(addr);   // reverse lookups are unaffected
        }

        /**
         * Addresses that are never filtered regardless of route state.
         * Loopback is the load-bearing one: without this exemption "localhost"
         * loses ::1 on a host with no IPv6 route, which breaks every guest that
         * talks to a local service. Link-local, wildcard and multicast are
         * exempt on the same principle -- none of them is reached via the
         * default route that the probe measures, so the probe says nothing
         * about whether they work.
         */
        private static boolean isAlwaysKept(InetAddress a) {
            return a.isLoopbackAddress()
                || a.isLinkLocalAddress()
                || a.isAnyLocalAddress()
                || a.isMulticastAddress();
        }
    }

    // -----------------------------------------------------------------------

    /**
     * Bionic's _have_ipv6 / _have_ipv4, in Java.
     *
     * A UDP connect() is a pure route lookup in the kernel -- no packets are
     * sent -- so this is cheap enough to do adaptively rather than deciding
     * once at startup. MEASURED on this host 2026-08-12: 100 IPv6 probes in
     * 28.61 ms (0.29 ms each), first call 14 ms including class loading. It is
     * still cached with a short TTL, because an app that resolves in a loop
     * would otherwise pay a syscall pair per lookup for an answer that changes
     * only when the network does.
     *
     * The TTL is what keeps this ADAPTIVE: joining or leaving an IPv6 network,
     * or bringing a VPN up, is picked up within TTL_NANOS instead of being
     * frozen at process start.
     */
    private static final class Probe {

        /** 2000:: -- the global-unicast target Bionic probes. */
        private static final byte[] V6_TARGET =
            {0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        /** 8.8.8.8 -- Bionic's IPv4 target. */
        private static final byte[] V4_TARGET = {8, 8, 8, 8};

        private static final long TTL_NANOS = 5_000_000_000L;   // 5s

        private static final ThreadLocal<Boolean> IN_PROBE = new ThreadLocal<>();

        private static volatile long stampNanos;
        private static volatile boolean cachedHave6 = true;
        private static volatile boolean cachedHave4 = true;
        private static volatile boolean everProbed;
        private static volatile boolean loggedFilter;

        static boolean inProbe() {
            return Boolean.TRUE.equals(IN_PROBE.get());
        }

        static boolean haveIpv6() { refresh(); return cachedHave6; }
        static boolean haveIpv4() { refresh(); return cachedHave4; }

        private static void refresh() {
            long now = System.nanoTime();
            // Benignly racy: two threads may probe concurrently and both write.
            // They compute the same answer from the same kernel state, so the
            // only cost is a duplicated 0.3 ms probe.
            if (everProbed && (now - stampNanos) < TTL_NANOS) return;
            IN_PROBE.set(Boolean.TRUE);
            try {
                boolean h6 = routable(true);
                boolean h4 = routable(false);
                cachedHave6 = h6;
                cachedHave4 = h4;
                stampNanos = System.nanoTime();
                if (!everProbed) {
                    everProbed = true;
                    if (!h6 || !h4) {
                        System.err.println("[I] Apk on Mac.addrconfig: AI_ADDRCONFIG probe"
                            + " -- have_ipv4=" + h4 + " have_ipv6=" + h6
                            + " (matching AOSP libcore; MACAPK_ADDRCONFIG=0 disables)");
                    }
                }
            } finally {
                IN_PROBE.remove();
            }
        }

        /**
         * One family's route probe. Mirrors Bionic's _find_src_addr: open a UDP
         * socket of that family, connect() to the well-known target, and see
         * whether the kernel could pick a source address.
         *
         * InetAddress.getByAddress(byte[]) constructs from RAW BYTES and
         * performs no name resolution, so this cannot re-enter the resolver.
         * (InetAddress.getByName would have been the recursion hazard.)
         */
        private static boolean routable(boolean v6) {
            try (DatagramChannel ch = DatagramChannel.open(
                    v6 ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET)) {
                InetAddress target = InetAddress.getByAddress(v6 ? V6_TARGET : V4_TARGET);
                ch.connect(new InetSocketAddress(target, 53));
                return ch.getLocalAddress() != null;
            } catch (IOException | RuntimeException e) {
                // ENETUNREACH / EHOSTUNREACH / EADDRNOTAVAIL all land here, and
                // all mean the same thing Bionic means by _have_ipvN() == 0.
                // RuntimeException covers UnsupportedOperationException, which
                // DatagramChannel.open(ProtocolFamily) throws on a host with the
                // family compiled out entirely -- also "no route" for our purpose.
                return false;
            }
        }

        /** One line, once, so the filter is observable in a runtime log. */
        static void noteFiltered(String host, int before, int after) {
            if (loggedFilter) return;
            loggedFilter = true;
            System.err.println("[I] Apk on Mac.addrconfig: filtered unroutable addresses for '"
                + host + "' (" + before + " -> " + after + "); further filtering is silent");
        }
    }
}
