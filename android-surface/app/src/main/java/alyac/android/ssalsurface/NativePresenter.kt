package alyac.android.ssalsurface

import android.view.Surface

internal class NativePresenter(socketAddr: String) {
    private var handle: Long = nativeCreate(socketAddr)

    fun setSurface(surface: Surface?, width: Int, height: Int) {
        if (handle != 0L) {
            nativeSetSurface(handle, surface, width, height)
        }
    }

    fun sendTouch(
        action: Int,
        pointerCount: Int,
        downTimeMs: Long,
        eventTimeMs: Long,
        ids: IntArray,
        xs: FloatArray,
        ys: FloatArray,
        pressures: FloatArray,
    ) {
        if (handle != 0L) {
            nativeSendTouch(
                handle,
                action,
                pointerCount,
                downTimeMs,
                eventTimeMs,
                ids,
                xs,
                ys,
                pressures,
            )
        }
    }

    fun sendKey(keyCode: Int, eventTimeMs: Long) {
        if (handle != 0L) {
            nativeSendKey(handle, keyCode, eventTimeMs)
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
    private external fun nativeSendTouch(
        handle: Long,
        action: Int,
        pointerCount: Int,
        downTimeMs: Long,
        eventTimeMs: Long,
        ids: IntArray,
        xs: FloatArray,
        ys: FloatArray,
        pressures: FloatArray,
    )
    private external fun nativeSendKey(handle: Long, keyCode: Int, eventTimeMs: Long)
    private external fun nativeDestroy(handle: Long)

    companion object {
        init {
            System.loadLibrary("ssal_presenter")
        }
    }
}
