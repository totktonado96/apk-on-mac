package androidx.window.extensions.area;
/** Status of a window area (rear display). Apk on Mac has none. */
public interface ExtensionWindowAreaStatus {
    int getWindowAreaStatus();
    android.util.DisplayMetrics getWindowAreaDisplayMetrics();
}
