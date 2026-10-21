// audio_input.h -- C API for real macOS microphone capture.
//
// Implemented by runtime/src/audio_input.mm. This is the INPUT counterpart of
// the macapk_audio_* output API in audio_backend.mm, and it is deliberately
// shaped the same way: an opaque int64 handle per stream, 0 meaning "no
// backend", and read/write helpers that speak the Android encodings.
//
// Consumers:
//   - android.media.AudioRecord (via com.macapk.loader.AudioInputBridge)
//   - a future OpenSL ES / AAudio recorder path can dlsym these directly,
//     the way the NDK media path already reaches macapk_md_* / macapk_vd_*.

#ifndef MACAPK_AUDIO_INPUT_H
#define MACAPK_AUDIO_INPUT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// macOS TCC microphone-authorization state. Mirrors AVAuthorizationStatus
// (AVCaptureDevice), which is the process-wide gate for ANY microphone access
// on macOS -- including the Core Audio / AVAudioEngine path this file uses.
enum {
    MACAPK_MIC_PERM_UNKNOWN    = 0,  // AVAuthorizationStatusNotDetermined
    MACAPK_MIC_PERM_GRANTED    = 1,  // AVAuthorizationStatusAuthorized
    MACAPK_MIC_PERM_DENIED     = 2,  // AVAuthorizationStatusDenied
    MACAPK_MIC_PERM_RESTRICTED = 3,  // AVAuthorizationStatusRestricted
};

// Current authorization state. Pure query -- never prompts, never opens the
// device, so it is safe to call from a feature-probe path.
int macapk_mic_permission(void);

// Open one capture stream delivering `sample_rate` Hz, `channels` channels,
// in Android `encoding` (2=PCM_16BIT, 3=PCM_8BIT, 4=PCM_FLOAT). Whatever the
// hardware actually provides is resampled and reformatted to match.
//
// Returns a handle > 0 only if capture is genuinely live: permission granted,
// an input device exists, the engine started, and a converter was built. It
// returns 0 otherwise, and the caller MUST report that as an uninitialized
// recorder rather than pretending to be initialized and yielding silence.
int64_t macapk_mic_open(int sample_rate, int channels, int encoding,
                        int buffer_frames);

void macapk_mic_start(int64_t h);
void macapk_mic_stop(int64_t h);
void macapk_mic_release(int64_t h);

// Drain captured audio in the stream's Android encoding. `blocking` != 0 waits
// until the full request is satisfied (bounded -- see the stall cap in the
// .mm); 0 returns immediately with whatever is buffered. Return values are
// element counts (bytes / int16s / floats), never negative.
int macapk_mic_read_bytes(int64_t h, uint8_t* dst, int nbytes, int blocking);
int macapk_mic_read_shorts(int64_t h, int16_t* dst, int nshorts, int blocking);
int macapk_mic_read_floats(int64_t h, float* dst, int nfloats, int blocking);

// Frames captured but not yet read (diagnostic / pacing).
int macapk_mic_buffered_frames(int64_t h);

// Nominal sample rate of the default input device, or 0 if none is open.
// Diagnostic: it tells you how much resampling the converter is doing.
int macapk_mic_hw_sample_rate(void);

#ifdef __cplusplus
}
#endif

#endif  // MACAPK_AUDIO_INPUT_H
