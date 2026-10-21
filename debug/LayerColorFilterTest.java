import android.graphics.Bitmap;
import android.graphics.BlendMode;
import android.graphics.BlendModeColorFilter;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.ColorMatrix;
import android.graphics.ColorMatrixColorFilter;
import android.graphics.LightingColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RecordingCanvas;
import android.graphics.RectF;
import android.graphics.RenderNode;

/**
 * Consumer-visible saveLayer regressions; no private framework hooks or native UI required.
 * From the repository root, using the framework jar under test:
 * javac -cp runtime/build/lib/android-framework.jar -d /tmp/layer-color-filter-test debug/LayerColorFilterTest.java
 * java -Djava.awt.headless=true -cp /tmp/layer-color-filter-test:runtime/build/lib/android-framework.jar LayerColorFilterTest
 *
 * All solid samples are exact ARGB comparisons. Shape samples deliberately avoid antialiased
 * edges; corners outside a diamond/L-shaped clip distinguish the shape from its bounding box.
 * Run with MACAPK_FRAMESPEED_LAYER=1 to exercise pooled layers explicitly as well.
 */
public final class LayerColorFilterTest {
    private static final int SIZE = 32;
    private static final int TRANSPARENT = 0x00000000;
    private static final int BLACK = 0xFF000000;
    private static final int WHITE = 0xFFFFFFFF;
    private static final int RED = 0xFFFF0000;
    private static final int GREEN = 0xFF00FF00;
    private static final int BLUE = 0xFF0000FF;
    // SpinnerSection.kt's orange, green, blue and amber item tints.
    private static final int[] SPINNER_TINTS = {
        0xFFFF5B29, 0xFF36D167, 0xFF3482FF, 0xFFFFB21D
    };
    private static int checks;
    private static int failures;

    public static void main(String[] args) {
        run("Spinner SRC_IN tint palette", LayerColorFilterTest::spinnerTints);
        run("ColorMatrix channel mapping", LayerColorFilterTest::matrixChannels);
        run("Lighting multiply and add", LayerColorFilterTest::lightingChannels);
        run("flatten overlapping fills before filtering", LayerColorFilterTest::groupFlattening);
        run("layer alpha precedes matrix alpha bias", LayerColorFilterTest::alphaBeforeFilter);
        run("filter precedes destination DST_IN blend", LayerColorFilterTest::filterBeforeBlend);
        run("null bounds and full alpha isolate a real layer", LayerColorFilterTest::nullBounds);
        run("Paint state snapshots at save", LayerColorFilterTest::paintSnapshot);
        run("mutable ColorMatrix filter snapshots at save", LayerColorFilterTest::matrixSnapshot);
        run("mutable Lighting filter snapshots at save", LayerColorFilterTest::lightingSnapshot);
        run("empty null-bounds layer respects initial nonrect clip", LayerColorFilterTest::initialClip);
        run("empty layer respects transformed bounds", LayerColorFilterTest::transformedBounds);
        run("zero layer alpha does not skip alpha-generating filter", LayerColorFilterTest::zeroAlpha);
        run("nested layer filtering composes inside out", LayerColorFilterTest::nestedLayers);
        run("reused layers contain no stale pixels or filters", LayerColorFilterTest::poolReuse);
        run("DST_IN color filter uses filter alpha", LayerColorFilterTest::destinationInFilter);
        run("SRC_ATOP color filter preserves destination alpha", LayerColorFilterTest::sourceAtopFilter);
        run("legacy MULTIPLY differs from BlendMode MULTIPLY", LayerColorFilterTest::multiplyModes);
        run("RenderNode recording and repeated replay snapshot filters", LayerColorFilterTest::renderNodeSnapshots);
        if (failures != 0) {
            throw new AssertionError(failures + " layer color filter regression(s) failed; "
                    + checks + " pixel comparisons reached");
        }
        System.out.println("LayerColorFilterTest PASS: " + checks + " exact pixel comparisons");
    }

    private static void run(String name, Runnable test) {
        try {
            test.run();
            System.out.println("PASS " + name);
        } catch (AssertionError | RuntimeException error) {
            failures++;
            System.err.println("FAIL " + name + ": " + error);
        }
    }

    private static final class Target {
        final Bitmap bitmap = Bitmap.createBitmap(SIZE, SIZE, Bitmap.Config.ARGB_8888);
        final Canvas canvas = new Canvas(bitmap);
    }

    private static Paint paint(int color) {
        Paint paint = new Paint();
        paint.setColor(color);
        paint.setAntiAlias(false);
        return paint;
    }

    private static Paint filtered(ColorFilter filter) {
        Paint paint = paint(WHITE);
        paint.setColorFilter(filter);
        return paint;
    }

    private static ColorMatrixColorFilter constant(int color) {
        return new ColorMatrixColorFilter(new float[] {
            0, 0, 0, 0, (color >>> 16) & 255,
            0, 0, 0, 0, (color >>> 8) & 255,
            0, 0, 0, 0, color & 255,
            0, 0, 0, 0, color >>> 24
        });
    }

    private static ColorMatrix cycleChannels() {
        // (r, g, b, a) -> (b, r, g, a), deliberately non-idempotent.
        return new ColorMatrix(new float[] {
            0, 0, 1, 0, 0,
            1, 0, 0, 0, 0,
            0, 1, 0, 0, 0,
            0, 0, 0, 1, 0
        });
    }

    private static void pixel(Target target, int x, int y, int expected, String label) {
        checks++;
        int actual = target.bitmap.getPixel(x, y);
        if (actual != expected) {
            throw new AssertionError(label + " at (" + x + "," + y + "): expected "
                    + String.format("#%08X", expected) + ", got " + String.format("#%08X", actual));
        }
    }

    private static void center(Target target, int expected, String label) {
        pixel(target, 16, 16, expected, label);
    }

    private static Target solidLayer(ColorFilter filter, int source) {
        Target target = new Target();
        int save = target.canvas.saveLayer(new RectF(4, 4, 28, 28), filtered(filter));
        target.canvas.drawRect(4, 4, 28, 28, paint(source));
        target.canvas.restoreToCount(save);
        return target;
    }

    private static void spinnerTints() {
        for (int tint : SPINNER_TINTS) {
            // Both public Android tint API families are used by Spinner/Compose consumers.
            Target modern = solidLayer(new BlendModeColorFilter(tint, BlendMode.SRC_IN), BLACK);
            center(modern, tint, "BlendMode Spinner tint");
            pixel(modern, 2, 2, TRANSPARENT, "BlendMode outside layer");
            Target legacy = solidLayer(new PorterDuffColorFilter(tint, PorterDuff.Mode.SRC_IN), BLACK);
            center(legacy, tint, "PorterDuff Spinner tint");
            pixel(legacy, 2, 2, TRANSPARENT, "PorterDuff outside layer");
        }
    }

    private static void matrixChannels() {
        Target target = solidLayer(new ColorMatrixColorFilter(cycleChannels()), 0xFF204060);
        center(target, 0xFF602040, "matrix maps flattened RGB");
    }

    private static void lightingChannels() {
        // R*1+0, G*0+16, B*1+64 (clamped): #4080E0 -> #4010FF.
        Target target = solidLayer(new LightingColorFilter(0x00FF00FF, 0x00001040), 0xFF4080E0);
        center(target, 0xFF4010FF, "lighting ignores operand alpha and clamps RGB");
        Target rounded = solidLayer(new LightingColorFilter(0xFFC8C8C8, 0), 0xFFC8C8C8);
        center(rounded, 0xFF9D9D9D, "lighting multiply rounds rather than truncates");
    }

    private static void groupFlattening() {
        Target target = new Target();
        ColorMatrixColorFilter halfAlpha = new ColorMatrixColorFilter(new float[] {
            1, 0, 0, 0, 0,
            0, 1, 0, 0, 0,
            0, 0, 1, 0, 0,
            0, 0, 0, 0.5f, 0
        });
        int save = target.canvas.saveLayer(new RectF(2, 2, 30, 30), filtered(halfAlpha));
        target.canvas.drawRect(4, 4, 20, 28, paint(BLACK));
        target.canvas.drawRect(12, 4, 28, 28, paint(BLACK));
        target.canvas.restoreToCount(save);
        pixel(target, 8, 16, 0x80000000, "one fill");
        center(target, 0x80000000, "overlap must not become alpha 192 from per-draw filtering");
        pixel(target, 24, 16, 0x80000000, "other fill");
    }

    private static void alphaBeforeFilter() {
        Target target = new Target();
        Paint layer = filtered(new ColorMatrixColorFilter(new float[] {
            1, 0, 0, 0, 0,
            0, 1, 0, 0, 0,
            0, 0, 1, 0, 0,
            0, 0, 0, 1, 127
        }));
        layer.setAlpha(128);
        int save = target.canvas.saveLayer(new RectF(4, 4, 28, 28), layer);
        target.canvas.drawRect(4, 4, 28, 28, paint(BLACK));
        target.canvas.restoreToCount(save);
        // 255 * 128/255 + 127 = 255, not (255 + 127 clamped) * 128/255 = 128.
        center(target, BLACK, "alpha bias follows layer alpha");
    }

    private static void filterBeforeBlend() {
        Target target = new Target();
        target.canvas.drawColor(WHITE);
        Paint layer = filtered(constant(0x80000000));
        layer.setBlendMode(BlendMode.DST_IN);
        int save = target.canvas.saveLayer(new RectF(4, 4, 28, 28), layer);
        target.canvas.drawRect(4, 4, 28, 28, paint(RED));
        target.canvas.restoreToCount(save);
        // Filtering first supplies mask alpha 128; the destination stays white, not black/red.
        center(target, 0x80FFFFFF, "filtered alpha masks destination");
        pixel(target, 1, 1, WHITE, "destination blend stays within saved bounds");
    }

    private static void nullBounds() {
        Target target = new Target();
        target.canvas.drawColor(BLUE);
        Paint layer = filtered(new BlendModeColorFilter(GREEN, BlendMode.SRC_IN));
        int save = target.canvas.saveLayer((RectF) null, layer);
        target.canvas.drawRect(8, 8, 24, 24, paint(BLACK));
        target.canvas.restoreToCount(save);
        center(target, GREEN, "null/full-alpha filtered layer must not degenerate to save");
        pixel(target, 2, 2, BLUE, "filter cannot recolor existing destination");
    }

    private static void paintSnapshot() {
        Target target = new Target();
        Paint layer = filtered(new BlendModeColorFilter(WHITE, BlendMode.SRC_IN));
        layer.setAlpha(128);
        int save = target.canvas.saveLayer(new RectF(4, 4, 28, 28), layer);
        layer.setAlpha(0);
        layer.setColorFilter(new BlendModeColorFilter(RED, BlendMode.SRC_IN));
        layer.setBlendMode(BlendMode.CLEAR);
        target.canvas.drawRect(4, 4, 28, 28, paint(BLACK));
        target.canvas.restoreToCount(save);
        center(target, 0x80FFFFFF, "saved Paint alpha/filter/blend are values, not live state");
    }

    private static void matrixSnapshot() {
        Target target = new Target();
        ColorMatrix matrix = cycleChannels();
        ColorMatrixColorFilter filter = new ColorMatrixColorFilter(matrix);
        Paint layer = filtered(filter);
        int save = target.canvas.saveLayer(new RectF(4, 4, 28, 28), layer);
        matrix.reset();
        filter.setColorMatrix(matrix);
        layer.setColorFilter(null);
        target.canvas.drawRect(4, 4, 28, 28, paint(0xFF204060));
        target.canvas.restoreToCount(save);
        center(target, 0xFF602040, "saved ColorMatrix filter survives mutation");
    }

    private static void lightingSnapshot() {
        Target target = new Target();
        LightingColorFilter filter = new LightingColorFilter(0x00FF00FF, 0x00001000);
        Paint layer = filtered(filter);
        int save = target.canvas.saveLayer(new RectF(4, 4, 28, 28), layer);
        filter.setColorMultiply(0);
        filter.setColorAdd(0x00FF0000);
        layer.setColorFilter(null);
        target.canvas.drawRect(4, 4, 28, 28, paint(0xFF4080C0));
        target.canvas.restoreToCount(save);
        center(target, 0xFF4010C0, "saved Lighting multiply/add survive mutation");
    }

    private static void initialClip() {
        Target target = new Target();
        target.canvas.drawColor(BLUE);
        Path clip = new Path();
        clip.moveTo(4, 4);
        clip.lineTo(28, 4);
        clip.lineTo(28, 12);
        clip.lineTo(12, 12);
        clip.lineTo(12, 28);
        clip.lineTo(4, 28);
        clip.close();
        target.canvas.clipPath(clip);
        int save = target.canvas.saveLayer((RectF) null, filtered(constant(RED)));
        // A filter sees the initial layer extent, not just the final narrowed drawing clip.
        target.canvas.clipRect(5, 5, 7, 7);
        target.canvas.restoreToCount(save); // Empty, but transparent black becomes opaque red.
        pixel(target, 20, 8, RED, "initial horizontal arm despite final clip");
        pixel(target, 8, 20, RED, "initial vertical arm");
        pixel(target, 20, 20, BLUE, "nonrect clip's missing corner");
        pixel(target, 2, 2, BLUE, "outside initial clip bounds");
        pixel(target, 30, 30, BLUE, "far outside initial clip");
    }

    private static void transformedBounds() {
        Target target = new Target();
        target.canvas.translate(16, 16);
        target.canvas.rotate(45);
        int save = target.canvas.saveLayer(new RectF(-6, -6, 6, 6), filtered(constant(RED)));
        target.canvas.restoreToCount(save);
        center(target, RED, "empty transformed layer center");
        pixel(target, 16, 10, RED, "diamond interior above center");
        pixel(target, 8, 8, TRANSPARENT, "upper-left bounding-box corner");
        pixel(target, 23, 8, TRANSPARENT, "upper-right bounding-box corner");
        pixel(target, 8, 23, TRANSPARENT, "lower-left bounding-box corner");
        pixel(target, 23, 23, TRANSPARENT, "lower-right bounding-box corner");
        pixel(target, 16, 5, TRANSPARENT, "outside diamond bounds");
    }

    private static void zeroAlpha() {
        Target target = new Target();
        Paint layer = filtered(constant(GREEN));
        layer.setAlpha(0);
        int save = target.canvas.saveLayer(new RectF(4, 4, 28, 28), layer);
        target.canvas.drawRect(8, 8, 24, 24, paint(RED));
        target.canvas.restoreToCount(save);
        center(target, GREEN, "filter regenerates alpha after zero paint alpha");
        pixel(target, 6, 6, GREEN, "transparent undrawn pixel also generates alpha");
        pixel(target, 2, 2, TRANSPARENT, "generated alpha cannot escape layer");
        Target hidden = new Target();
        Paint reveal = filtered(new ColorMatrixColorFilter(new float[] {
            1, 0, 0, 0, 0,
            0, 1, 0, 0, 0,
            0, 0, 1, 0, 0,
            0, 0, 0, 0, 255
        }));
        reveal.setAlpha(0);
        save = hidden.canvas.saveLayer(new RectF(4, 4, 28, 28), reveal);
        hidden.canvas.drawRect(8, 8, 24, 24, paint(RED));
        hidden.canvas.restoreToCount(save);
        center(hidden, BLACK, "zero premultiplied input must not reveal hidden red RGB");
    }

    private static void nestedLayers() {
        Target target = new Target();
        int outer = target.canvas.saveLayer(new RectF(4, 4, 28, 28),
                filtered(new ColorMatrixColorFilter(new float[] {
                    0, 1, 0, 0, 0,
                    1, 0, 0, 0, 0,
                    0, 0, 1, 0, 0,
                    0, 0, 0, 1, 0
                })));
        target.canvas.drawRect(4, 4, 8, 8, paint(BLUE));
        int inner = target.canvas.saveLayer(new RectF(8, 8, 24, 24), filtered(constant(RED)));
        target.canvas.restoreToCount(inner);
        target.canvas.restoreToCount(outer);
        center(target, GREEN, "inner red is mapped to green by outer filter exactly once");
        pixel(target, 6, 6, BLUE, "outer-only draw survives nested restore");
        pixel(target, 26, 26, TRANSPARENT, "outer untouched pixels stay transparent");
        pixel(target, 2, 2, TRANSPARENT, "nested filters stay inside outer bounds");
    }

    private static void poolReuse() {
        Target target = new Target();
        // Same-sized layers become eligible for reuse. Do not inspect pool implementation state.
        int save = target.canvas.saveLayer(new RectF(0, 0, SIZE, SIZE), filtered(constant(RED)));
        target.canvas.restoreToCount(save);
        center(target, RED, "first layer seeds all pooled pixels");
        target.canvas.drawColor(TRANSPARENT, PorterDuff.Mode.CLEAR);
        save = target.canvas.saveLayer(new RectF(0, 0, SIZE, SIZE),
                filtered(new LightingColorFilter(0x00FFFFFF, 0)));
        target.canvas.restoreToCount(save);
        center(target, TRANSPARENT, "empty reused layer has no old pixels");
        pixel(target, 1, 1, TRANSPARENT, "reused boundary is cleared");
        save = target.canvas.saveLayer(new RectF(0, 0, SIZE, SIZE), paint(WHITE));
        target.canvas.drawRect(12, 12, 20, 20, paint(BLACK));
        target.canvas.restoreToCount(save);
        center(target, BLACK, "unfiltered next layer has no stale red filter");
        pixel(target, 1, 1, TRANSPARENT, "unfiltered next layer has no stale extent");
    }

    private static void destinationInFilter() {
        Target target = solidLayer(new BlendModeColorFilter(0x80FFFFFF, BlendMode.DST_IN), WHITE);
        center(target, 0x80FFFFFF, "DST_IN filter multiplies destination alpha by tint alpha");
    }

    private static void sourceAtopFilter() {
        Target target = solidLayer(new PorterDuffColorFilter(0x80FF0000, PorterDuff.Mode.SRC_ATOP), BLUE);
        center(target, 0xFF80007F, "half red atop opaque blue is opaque red/blue mix");
    }

    private static void multiplyModes() {
        // Legacy MULTIPLY is Skia modulate (alpha product), modern MULTIPLY is the blend mode.
        Target legacy = solidLayer(new PorterDuffColorFilter(0x80FFFFFF, PorterDuff.Mode.MULTIPLY), TRANSPARENT);
        center(legacy, TRANSPARENT, "legacy MULTIPLY against transparent pixel");
        Target modern = solidLayer(new BlendModeColorFilter(0x80FFFFFF, BlendMode.MULTIPLY), TRANSPARENT);
        center(modern, 0x80FFFFFF, "BlendMode MULTIPLY retains source over transparent pixel");
        pixel(modern, 2, 2, TRANSPARENT, "alpha-generating MULTIPLY stays bounded");
        Target destination = new Target();
        destination.canvas.drawColor(0x80FFFFFF);
        Paint layer = filtered(new LightingColorFilter(WHITE, 0));
        layer.setXfermode(new android.graphics.PorterDuffXfermode(PorterDuff.Mode.MULTIPLY));
        int save = destination.canvas.saveLayer(new RectF(4, 4, 28, 28), layer);
        destination.canvas.drawRect(4, 4, 28, 28, paint(0x80FFFFFF));
        destination.canvas.restoreToCount(save);
        center(destination, 0x40FFFFFF, "legacy destination multiply uses alpha product");
    }

    private static void renderNodeSnapshots() {
        RenderNode node = new RenderNode("LayerColorFilterTest");
        node.setPosition(0, 0, SIZE, SIZE);
        ColorMatrixColorFilter matrix = new ColorMatrixColorFilter(cycleChannels());
        LightingColorFilter lighting = new LightingColorFilter(0x00FF00FF, 0x00001000);
        Paint left = filtered(matrix);
        Paint right = filtered(lighting);
        RecordingCanvas recording = node.beginRecording(SIZE, SIZE);
        int save = recording.saveLayer(new RectF(0, 0, 16, SIZE), left);
        matrix.setColorMatrix(new ColorMatrix());
        left.setAlpha(0);
        recording.drawRect(0, 0, 16, SIZE, paint(0xFF204060));
        recording.restoreToCount(save);
        save = recording.saveLayer(new RectF(16, 0, SIZE, SIZE), right);
        lighting.setColorMultiply(0);
        lighting.setColorAdd(0x00FF0000);
        right.setColorFilter(null);
        recording.drawRect(16, 0, SIZE, SIZE, paint(0xFF4080C0));
        recording.restoreToCount(save);
        node.endRecording();
        // Mutate again after committing: neither replay may observe later filter/Paint state.
        matrix.setColorMatrix(cycleChannels());
        lighting.setColorAdd(0x000000FF);
        left.setColorFilter(null);
        right.setAlpha(0);
        Target first = new Target();
        first.canvas.drawRenderNode(node);
        pixel(first, 8, 16, 0xFF602040, "recorded matrix snapshot");
        pixel(first, 24, 16, 0xFF4010C0, "recorded Lighting snapshot");
        Target second = new Target();
        second.canvas.drawColor(GREEN);
        second.canvas.drawRenderNode(node);
        pixel(second, 8, 16, 0xFF602040, "matrix second replay is stable");
        pixel(second, 24, 16, 0xFF4010C0, "Lighting second replay is stable");
    }
}
