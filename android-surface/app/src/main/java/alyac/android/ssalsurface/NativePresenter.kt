package alyac.android.ssalsurface

import android.view.Surface

internal class NativePresenter(socketAddr: String) {
    private var handle: Long = nativeCreate(socketAddr)

    fun setSurface(surface: Surface?, width: Int, height: Int) {
        if (handle != 0L) {
            nativeSetSurface(handle, surface, width, height)
        }
    }

    fun close() {
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0L
        }
    }

    private external fun nativeCreate(socketAddr: String): Long
    private external fun nativeSetSurface(handle: Long, surface: Surface?, width: Int, height: Int)
    private external fun nativeDestroy(handle: Long)

    companion object {
        init {
            System.loadLibrary("ssal_presenter")
        }
    }
}
