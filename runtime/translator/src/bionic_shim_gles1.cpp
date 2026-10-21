// bionic_shim_gles1.cpp -- ARM32-lifted-tier ("__macapk_shim_*") entry points
// for OpenGL ES 1.1 FIXED-FUNCTION and GL_OES_framebuffer_object.
//
// WHY THIS FILE EXISTS
// --------------------
// main.cpp's kPointerAwareImports carried 85 ES2 names and ZERO ES1 names.
// resolve_import() (main.cpp, the `kPointerAwareImports.count(nm) || ...`
// branch) only builds the "__macapk_shim_" + name form for members of the
// three curated sets; a name in none of them falls through to the BARE
// symbol. That fallback is NOT the panic stub for ES1, because the shim
// dylib links libGLESv2 and ANGLE implements ES 1.1 natively: every one of
// the 31 names below was verified present in our libGLESv2.dylib with
// `nm -gU`. So the bare bind SUCCEEDS, the import stops being reported as
// unresolved, and ANGLE is called DIRECTLY with the guest's 32-bit vaddrs
// used as 64-bit host pointers.
//
// The measured symptom on Jetpack Joyride (com.halfbrick.jetpackjoyride
// 1.3.5, armeabi-only, Halfbrick Mortar engine) was a SEGV with pc inside
// libGLESv2 in angle::Mat4::Mat4(const float*) -- i.e. ANGLE's ES1 matrix
// stack dereferencing the guest vaddr handed to glLoadMatrixf/glMultMatrixf.
// That is strictly WORSE than a missing shim, which at least fails loudly.
// This is the same trap as v1.0.820's 24 dead-code shims and the v1.0.833
// GLES2 batch: writing the shim is only HALF the job, adding the name to
// kPointerAwareImports is the other half, and the only honest verification
// is `nm -u` on a produced dylib (the unresolved COUNT looks identical
// whether the binds are right or wrong).
//
// WHY A SEPARATE TU: bionic_shim.cpp (39k+ lines) is owned by other lanes in
// this multi-lane session. Precedent for a self-contained shim TU added to
// the same macapk-bionic-shim target: bionic_shim_arm32.cpp,
// bionic_shim_signal.cpp, bionic_shim_jni_bare.cpp, bionic_shim_elfexec.cpp.
// The ONLY cross-TU dependency taken here is __macapk_get_guest_base(),
// the blessed accessor every translated dylib's constructor already calls.
// Small helpers (guest_base/gptr) are DELIBERATELY duplicated rather than
// hoisted into a shared header, per the standing lane-ownership split.
//
// THE THREE ABI HAZARDS THIS FILE EXISTS TO FIX
// ---------------------------------------------
// 1. POINTER ARGS. glLoadMatrixf/glMultMatrixf take a const GLfloat*; the
//    four gl*Pointer entries take a const void*; six OES entries take a
//    GLuint*/GLint*. All arrive as 32-bit guest vaddrs and must be rebased
//    onto the guest arena before ANGLE dereferences them.
//
// 2. SOFT-FLOAT. glColor4f(GLfloat,GLfloat,GLfloat,GLfloat) is the trap that
//    does not crash. ARM32 AAPCS soft-float passes the four floats as raw
//    BITS in r0-r3; Apple arm64 passes them in s0-s3. A bare bind therefore
//    hands ANGLE whatever happens to be in the FP registers -- a silently
//    wrong vertex colour, never a fault. Each arg is bit-cast here.
//
// 3. VBO-vs-CLIENT-MEMORY on the four gl*Pointer entries. See the long
//    comment on array_ptr() below; getting this backwards corrupts working
//    apps in BOTH directions, and neither direction reliably faults.
//
// C++17. No em dashes (project convention).

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(MACAPK_HAS_ANGLE)
// Both defines are REQUIRED, and the first one is a genuine trap.
//
// thirdparty/angle/include/GLES2/gl2.h self-defaults GL_GLES_PROTOTYPES to 1
// (its lines 24-25), so ES2 code gets prototypes just by including it. The
// vendored ES1 header does NOT: GLES/gl.h TESTS `#if GL_GLES_PROTOTYPES` at
// line 552 but never defines it, and an undefined identifier in #if
// evaluates to 0 -- so including GLES/gl.h alone yields the enums and the
// PFN typedefs but ZERO function declarations, and every ES1 call fails with
// "use of undeclared identifier". Nothing warns that a header silently gave
// you half its contents.
//
// GLES/glext.h separately gates the GL_OES_framebuffer_object prototypes on
// GL_GLEXT_PROTOTYPES being defined at all (its lines 58/69/81), which is the
// normal Khronos convention for extension headers.
#define GL_GLES_PROTOTYPES 1
#define GL_GLEXT_PROTOTYPES
// ANGLE's ES1 headers (thirdparty/angle/include). Deliberately NOT combined
// with <GLES2/gl2.h> in one TU -- the ES1 and ES2 headers redeclare the same
// tokens. This file is ES1-only, bionic_shim.cpp is ES2-only.
#include <GLES/gl.h>
#include <GLES/glext.h>
#endif

// Exported by bionic_shim.cpp (see that file's allocate_guest_memory /
// g_guest_base). Stable, already load-bearing fleet-wide: every translated
// ARM32 dylib's module constructor calls it.
extern "C" void* __macapk_get_guest_base(void);

namespace {

inline uint8_t* guest_base() {
    return static_cast<uint8_t*>(__macapk_get_guest_base());
}

// Guest vaddr -> host pointer, honouring the project-wide "0 means null"
// convention. Deliberate duplicate of bionic_shim.cpp's file-local gptr().
inline void* gptr(uint32_t guest_addr) {
    uint8_t* base = guest_base();
    if (!base || !guest_addr) return nullptr;
    return base + guest_addr;
}

// ARM32 AAPCS soft-float: a float argument arrives as its raw 32-bit
// encoding in a core register. Reinterpret, never convert -- a
// static_cast<float>(uint32_t) would turn the BIT PATTERN into a value.
inline float f32(uint32_t bits) {
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// Read the Nth stack-spilled ARM32 argument. AAPCS spills args 5+ at
// sp+0, sp+4, ... Mirrors bionic_shim.cpp's stack_arg().
inline uint32_t stack_arg(uint32_t sp, int idx) {
    uint8_t* base = guest_base();
    if (sp == 0 || base == nullptr) return 0;
    uint32_t v = 0;
    std::memcpy(&v, base + sp + idx * 4, sizeof(v));
    return v;
}

// First-call-per-function trace. Proves the ES1 import actually reached OUR
// shim rather than binding bare to ANGLE, which is the entire failure mode
// this file addresses and is otherwise indistinguishable in the log. Shares
// the "[I] gles" prefix with bionic_shim.cpp's note_gl_call so existing log
// greps keep working; the "1" disambiguates the tier.
inline void note_gles1_call(const char* fn) {
    static thread_local const char* t_last = nullptr;
    if (fn == t_last) return;
    t_last = fn;
    static std::atomic<int> logged{0};
    if (logged.fetch_add(1, std::memory_order_relaxed) < 48)
        std::fprintf(stderr, "[I] gles1: shim %s\n", fn);
}

#if defined(MACAPK_HAS_ANGLE)

// ---------------------------------------------------------------------
// The VBO-vs-client-memory rule for glVertexPointer / glTexCoordPointer /
// glColorPointer / glNormalPointer.
//
// The final `pointer` argument has DUAL meaning, and the discriminator is
// the ARRAY_BUFFER binding CURRENT AT THE TIME OF THIS CALL. Verbatim from
// the OpenGL ES Full Specification 1.1.12 (2008-04-24) section 2.9.1
// "Vertex Arrays in Buffer Objects", page 25:
//
//   "The client state associated with each vertex array type includes a
//    buffer object binding point. The commands that specify the locations
//    and organizations of vertex arrays copy the buffer object name that
//    is bound to ARRAY BUFFER to the binding point corresponding to the
//    vertex array of the type being specified."
//
//   "Rendering commands DrawArrays and DrawElements operate as previously
//    defined, except that data for enabled vertex arrays are sourced from
//    buffers if the array's buffer binding is non-zero. When an array is
//    sourced from a buffer object, the pointer value of that array is used
//    to compute an offset, in basic machine units, into the data store of
//    the buffer object. This offset is computed by subtracting a null
//    pointer from the pointer value, where both pointers are treated as
//    pointers to basic machine units."
//
// So when a buffer IS bound the value is an OFFSET and must pass through
// BIT-FOR-BIT -- translating it would corrupt the geometry. When no buffer
// is bound it is a genuine client-memory address and MUST be rebased.
// Both error directions produce garbage rather than a fault: translating a
// small offset (0/12/24) yields a wild pointer, and passing a real address
// through as an offset yields a huge out-of-range offset.
//
// Two further consequences the spec pins down, both honoured here:
//
//  - The decision is made NOW, not at draw time ("the commands ... copy
//    the buffer object name"), so a later glBindBuffer cannot retroactively
//    change it. That is why this is evaluated per gl*Pointer call.
//  - Client array data is consumed LAZILY at draw time (spec 2.8
//    "Transferring Array Elements": "When an array element i is transferred
//    to the GL by the DrawArrays or DrawElements commands"). So the
//    translated address must stay valid AND stay content-coherent with the
//    guest's memory until the draw. Rebasing onto the guest arena satisfies
//    both: the host pointer ALIASES the guest's live bytes, so a guest that
//    refills the array every frame after a one-time gl*Pointer call (a very
//    common engine pattern) is handled correctly. Copying/snapshotting the
//    data here would render stale geometry -- do not "optimize" this into a
//    memcpy.
//
// This is exactly the rule bionic_shim.cpp's __macapk_shim_glVertexAttribPointer
// (ES2) and __macapk_shim_glDrawElements already implement; kept identical
// on purpose so the two tiers cannot drift. glDrawArrays/glDrawElements are
// already shimmed there and need no change here -- glDrawElements branches
// on ELEMENT_ARRAY_BUFFER_BINDING at DRAW time, correctly, because it has no
// earlier pointer-setting call to capture.
// ---------------------------------------------------------------------
inline const void* array_ptr(uint32_t guest_ptr) {
    GLint bound = 0;
    glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &bound);
    if (bound == 0 && guest_ptr != 0)
        return static_cast<const void*>(guest_base() + guest_ptr);
    // Buffer bound: `guest_ptr` is an offset into that buffer's data store.
    // Pass through verbatim. Also covers guest_ptr == 0, which means the
    // same thing (null / offset zero) under either reading.
    return reinterpret_cast<const void*>(static_cast<uintptr_t>(guest_ptr));
}

#endif  // MACAPK_HAS_ANGLE

}  // namespace

// When ANGLE is absent the shims must still EXIST and link, so a translated
// APK that imports them still loads (it just will not render) -- same
// contract bionic_shim.cpp's gl* wrappers follow. MACAPK_GL1 keeps that
// conditional in one place instead of an #if per function.
#if defined(MACAPK_HAS_ANGLE)
#define MACAPK_GL1(expr) do { expr; } while (0)
#else
#define MACAPK_GL1(expr) do { } while (0)
#endif

extern "C" {

// =====================================================================
// Matrix stack. Signatures verified against thirdparty/angle/include/GLES/gl.h
// and the ES 1.1 spec.
// =====================================================================

uint32_t __macapk_shim_glMatrixMode(uint32_t mode, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glMatrixMode");
    MACAPK_GL1(glMatrixMode(mode));
    return 0;
}

uint32_t __macapk_shim_glLoadIdentity(uint32_t, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glLoadIdentity");
    MACAPK_GL1(glLoadIdentity());
    return 0;
}

uint32_t __macapk_shim_glPushMatrix(uint32_t, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glPushMatrix");
    MACAPK_GL1(glPushMatrix());
    return 0;
}

uint32_t __macapk_shim_glPopMatrix(uint32_t, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glPopMatrix");
    MACAPK_GL1(glPopMatrix());
    return 0;
}

// void glLoadMatrixf(const GLfloat *m) -- 16 floats.
// THE CONFIRMED CRASH SITE: bare-bound, ANGLE built angle::Mat4 straight off
// the guest vaddr and SEGV'd. `m` is never an offset (no buffer-object form
// exists for the matrix commands), so it is ALWAYS a plain rebase.
uint32_t __macapk_shim_glLoadMatrixf(uint32_t m, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glLoadMatrixf");
    MACAPK_GL1(glLoadMatrixf(static_cast<const GLfloat*>(gptr(m))));
    return 0;
}

// void glMultMatrixf(const GLfloat *m) -- same as above.
uint32_t __macapk_shim_glMultMatrixf(uint32_t m, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glMultMatrixf");
    MACAPK_GL1(glMultMatrixf(static_cast<const GLfloat*>(gptr(m))));
    return 0;
}

// =====================================================================
// Client state + immediate-mode fixed function.
// =====================================================================

uint32_t __macapk_shim_glEnableClientState(uint32_t array, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glEnableClientState");
    MACAPK_GL1(glEnableClientState(array));
    return 0;
}

uint32_t __macapk_shim_glDisableClientState(uint32_t array, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glDisableClientState");
    MACAPK_GL1(glDisableClientState(array));
    return 0;
}

uint32_t __macapk_shim_glClientActiveTexture(uint32_t texture, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glClientActiveTexture");
    MACAPK_GL1(glClientActiveTexture(texture));
    return 0;
}

// void glColor4f(GLfloat red, GLfloat green, GLfloat blue, GLfloat alpha)
// HAZARD 2 (see file banner): four soft-float args arriving as raw bits in
// r0-r3. A bare bind does not crash, it just draws the wrong colour -- which
// is why this one would have survived a "no more SEGVs" verdict unnoticed.
uint32_t __macapk_shim_glColor4f(uint32_t r, uint32_t g, uint32_t b, uint32_t a) {
    note_gles1_call("glColor4f");
    MACAPK_GL1(glColor4f(f32(r), f32(g), f32(b), f32(a)));
    return 0;
}

// void glTexEnvi(GLenum target, GLenum pname, GLint param) -- param is SIGNED.
uint32_t __macapk_shim_glTexEnvi(uint32_t target, uint32_t pname, uint32_t param, uint32_t) {
    note_gles1_call("glTexEnvi");
    MACAPK_GL1(glTexEnvi(target, pname, static_cast<GLint>(param)));
    return 0;
}

// glCullFace exists in BOTH ES1 and ES2 but was in neither curated set, so
// the ARM32 tier bound it bare. Harmless today (one enum arg, no pointer, no
// float), shimmed for uniform tracing and so the ES1 set is complete rather
// than "complete except the one that happens to be safe".
uint32_t __macapk_shim_glCullFace(uint32_t mode, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glCullFace");
    MACAPK_GL1(glCullFace(mode));
    return 0;
}

// =====================================================================
// Vertex arrays. The `pointer` arg is dual-meaning -- see array_ptr().
// =====================================================================

// void glVertexPointer(GLint size, GLenum type, GLsizei stride, const void *pointer)
uint32_t __macapk_shim_glVertexPointer(uint32_t size, uint32_t type,
                                       uint32_t stride, uint32_t pointer) {
    note_gles1_call("glVertexPointer");
    MACAPK_GL1(glVertexPointer(static_cast<GLint>(size), type,
                               static_cast<GLsizei>(stride),
                               array_ptr(pointer)));
    return 0;
}

// void glTexCoordPointer(GLint size, GLenum type, GLsizei stride, const void *pointer)
uint32_t __macapk_shim_glTexCoordPointer(uint32_t size, uint32_t type,
                                         uint32_t stride, uint32_t pointer) {
    note_gles1_call("glTexCoordPointer");
    MACAPK_GL1(glTexCoordPointer(static_cast<GLint>(size), type,
                                 static_cast<GLsizei>(stride),
                                 array_ptr(pointer)));
    return 0;
}

// void glColorPointer(GLint size, GLenum type, GLsizei stride, const void *pointer)
uint32_t __macapk_shim_glColorPointer(uint32_t size, uint32_t type,
                                      uint32_t stride, uint32_t pointer) {
    note_gles1_call("glColorPointer");
    MACAPK_GL1(glColorPointer(static_cast<GLint>(size), type,
                              static_cast<GLsizei>(stride),
                              array_ptr(pointer)));
    return 0;
}

// void glNormalPointer(GLenum type, GLsizei stride, const void *pointer)
// THREE args, not four: ES 1.1 section 2.8 -- "Because normals are always
// specified with three values ... NormalPointer and PointSizePointerOES have
// no size argument." An easy off-by-one against its three siblings.
uint32_t __macapk_shim_glNormalPointer(uint32_t type, uint32_t stride,
                                       uint32_t pointer, uint32_t) {
    note_gles1_call("glNormalPointer");
    MACAPK_GL1(glNormalPointer(type, static_cast<GLsizei>(stride),
                               array_ptr(pointer)));
    return 0;
}

// =====================================================================
// GL_OES_framebuffer_object. ES 1.1 has no core FBO; render-to-texture goes
// through this extension, and ANGLE exports every entry point (verified with
// nm -gU on our libGLESv2.dylib). Signatures verified against
// thirdparty/angle/include/GLES/glext.h, which matches the extension spec's
// "New Procedures and Functions" block verbatim.
//
// Return types are NOT uniform: glCheckFramebufferStatusOES returns GLenum
// (4 bytes) and glIs{Framebuffer,Renderbuffer}OES return GLboolean (ONE
// byte, a GLubyte -- not int). Both are widened to the shim's uint32_t
// return here, which is what the lifted call site reads out of r0.
// =====================================================================

uint32_t __macapk_shim_glBindFramebufferOES(uint32_t target, uint32_t fb, uint32_t, uint32_t) {
    note_gles1_call("glBindFramebufferOES");
    MACAPK_GL1(glBindFramebufferOES(target, fb));
    return 0;
}

uint32_t __macapk_shim_glBindRenderbufferOES(uint32_t target, uint32_t rb, uint32_t, uint32_t) {
    note_gles1_call("glBindRenderbufferOES");
    MACAPK_GL1(glBindRenderbufferOES(target, rb));
    return 0;
}

uint32_t __macapk_shim_glCheckFramebufferStatusOES(uint32_t target, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glCheckFramebufferStatusOES");
#if defined(MACAPK_HAS_ANGLE)
    return static_cast<uint32_t>(glCheckFramebufferStatusOES(target));
#else
    (void)target;
    return 0;
#endif
}

// void glDeleteFramebuffersOES(GLsizei n, const GLuint *framebuffers)
uint32_t __macapk_shim_glDeleteFramebuffersOES(uint32_t n, uint32_t fbs, uint32_t, uint32_t) {
    note_gles1_call("glDeleteFramebuffersOES");
    MACAPK_GL1(glDeleteFramebuffersOES(static_cast<GLsizei>(n),
                                       static_cast<const GLuint*>(gptr(fbs))));
    return 0;
}

// void glDeleteRenderbuffersOES(GLsizei n, const GLuint *renderbuffers)
uint32_t __macapk_shim_glDeleteRenderbuffersOES(uint32_t n, uint32_t rbs, uint32_t, uint32_t) {
    note_gles1_call("glDeleteRenderbuffersOES");
    MACAPK_GL1(glDeleteRenderbuffersOES(static_cast<GLsizei>(n),
                                        static_cast<const GLuint*>(gptr(rbs))));
    return 0;
}

// void glGenFramebuffersOES(GLsizei n, GLuint *framebuffers) -- OUT pointer.
uint32_t __macapk_shim_glGenFramebuffersOES(uint32_t n, uint32_t fbs, uint32_t, uint32_t) {
    note_gles1_call("glGenFramebuffersOES");
    MACAPK_GL1(glGenFramebuffersOES(static_cast<GLsizei>(n),
                                    static_cast<GLuint*>(gptr(fbs))));
    return 0;
}

// void glGenRenderbuffersOES(GLsizei n, GLuint *renderbuffers) -- OUT pointer.
uint32_t __macapk_shim_glGenRenderbuffersOES(uint32_t n, uint32_t rbs, uint32_t, uint32_t) {
    note_gles1_call("glGenRenderbuffersOES");
    MACAPK_GL1(glGenRenderbuffersOES(static_cast<GLsizei>(n),
                                     static_cast<GLuint*>(gptr(rbs))));
    return 0;
}

uint32_t __macapk_shim_glFramebufferRenderbufferOES(uint32_t target, uint32_t attachment,
                                                    uint32_t rbtarget, uint32_t rb) {
    note_gles1_call("glFramebufferRenderbufferOES");
    MACAPK_GL1(glFramebufferRenderbufferOES(target, attachment, rbtarget, rb));
    return 0;
}

// void glFramebufferTexture2DOES(GLenum target, GLenum attachment,
//                                GLenum textarget, GLuint texture, GLint level)
// FIVE args: `level` spills to the caller stack under AAPCS32, so this shim
// takes the extra `sp` param and must ALSO be listed in
// kPointerAwareWideImports (wide is ADDITIVE to kPointerAwareImports, not an
// alternative). It is the only ES1/OES name here that needs SP.
uint32_t __macapk_shim_glFramebufferTexture2DOES(uint32_t target, uint32_t attachment,
                                                 uint32_t textarget, uint32_t texture,
                                                 uint32_t sp) {
    note_gles1_call("glFramebufferTexture2DOES");
    const uint32_t level = stack_arg(sp, 0);
    MACAPK_GL1(glFramebufferTexture2DOES(target, attachment, textarget, texture,
                                         static_cast<GLint>(level)));
    return 0;
}

uint32_t __macapk_shim_glGenerateMipmapOES(uint32_t target, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glGenerateMipmapOES");
    MACAPK_GL1(glGenerateMipmapOES(target));
    return 0;
}

// void glGetFramebufferAttachmentParameterivOES(GLenum target, GLenum attachment,
//                                               GLenum pname, GLint *params)
uint32_t __macapk_shim_glGetFramebufferAttachmentParameterivOES(
        uint32_t target, uint32_t attachment, uint32_t pname, uint32_t params) {
    note_gles1_call("glGetFramebufferAttachmentParameterivOES");
    MACAPK_GL1(glGetFramebufferAttachmentParameterivOES(
        target, attachment, pname, static_cast<GLint*>(gptr(params))));
    return 0;
}

// void glGetRenderbufferParameterivOES(GLenum target, GLenum pname, GLint *params)
uint32_t __macapk_shim_glGetRenderbufferParameterivOES(uint32_t target, uint32_t pname,
                                                       uint32_t params, uint32_t) {
    note_gles1_call("glGetRenderbufferParameterivOES");
    MACAPK_GL1(glGetRenderbufferParameterivOES(
        target, pname, static_cast<GLint*>(gptr(params))));
    return 0;
}

uint32_t __macapk_shim_glIsFramebufferOES(uint32_t fb, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glIsFramebufferOES");
#if defined(MACAPK_HAS_ANGLE)
    return glIsFramebufferOES(fb) ? 1u : 0u;
#else
    (void)fb;
    return 0;
#endif
}

uint32_t __macapk_shim_glIsRenderbufferOES(uint32_t rb, uint32_t, uint32_t, uint32_t) {
    note_gles1_call("glIsRenderbufferOES");
#if defined(MACAPK_HAS_ANGLE)
    return glIsRenderbufferOES(rb) ? 1u : 0u;
#else
    (void)rb;
    return 0;
#endif
}

uint32_t __macapk_shim_glRenderbufferStorageOES(uint32_t target, uint32_t internalformat,
                                                uint32_t width, uint32_t height) {
    note_gles1_call("glRenderbufferStorageOES");
    MACAPK_GL1(glRenderbufferStorageOES(target, internalformat,
                                        static_cast<GLsizei>(width),
                                        static_cast<GLsizei>(height)));
    return 0;
}

}  // extern "C"
