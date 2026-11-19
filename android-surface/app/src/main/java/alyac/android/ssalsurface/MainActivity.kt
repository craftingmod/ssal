package alyac.android.ssalsurface

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.os.Bundle
import android.os.FileObserver
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import java.io.File
import java.io.IOException

class MainActivity : AppCompatActivity(), SurfaceHolder.Callback {
    private lateinit var surfaceHolder: SurfaceHolder
    private val frame = Bitmap.createBitmap(4, 4, Bitmap.Config.ARGB_8888).apply {
        eraseColor(Color.RED)
    }
    private val paint = Paint().apply { isFilterBitmap = false }
    private val destination = Rect()
    private var resumed = false
    private var surfaceReady = false
    private var surfaceWidth = 0
    private var surfaceHeight = 0
    private var inbox: File? = null
    private var presenterSocket: String? = null
    private var nativePresenter: NativePresenter? = null
    private var receiver: HandlerThread? = null
    private var observer: FileObserver? = null
    private var hasFrame = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
        surfaceHolder = findViewById<SurfaceView>(R.id.presenter_surface).holder
        surfaceHolder.addCallback(this)
        val session = intent.getStringExtra("presenter_session")
        if (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0 &&
            session != null && session.matches(Regex("[0-9a-f]{32}"))
        ) {
            inbox = File(cacheDir, "ssal-frame-$session")
            hasFrame = false
        } else {
            val socketExtra = intent.getStringExtra("presenter_socket")
            if (socketExtra != "none") {
                presenterSocket = socketExtra?.takeIf { it.isNotEmpty() }
                    ?: File(cacheDir, "ssal-presenter.sock").absolutePath
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        inbox?.let(::watchFrames)
        presenterSocket?.let { addr ->
            if (nativePresenter == null) {
                nativePresenter = NativePresenter(addr)
                if (surfaceReady && surfaceHolder.surface.isValid) {
                    nativePresenter?.setSurface(surfaceHolder.surface, surfaceWidth, surfaceHeight)
                }
            }
        }
        present()
    }

    override fun onPause() {
        resumed = false
        nativePresenter?.close()
        nativePresenter = null
        observer?.stopWatching()
        observer = null
        receiver?.quitSafely()
        receiver = null
        Log.i("SsalPresenter", "Activity paused")
        super.onPause()
    }

    override fun onDestroy() {
        surfaceHolder.removeCallback(this)
        frame.recycle()
        Log.i("SsalPresenter", "Activity destroyed, callback removed and bitmap recycled")
        super.onDestroy()
    }

    override fun surfaceCreated(holder: SurfaceHolder) {
        Log.i("SsalPresenter", "Surface created")
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
        surfaceWidth = width
        surfaceHeight = height
        surfaceReady = width > 0 && height > 0
        Log.i("SsalPresenter", "Surface changed: ${width}x${height}")
        if (surfaceReady) {
            nativePresenter?.setSurface(holder.surface, width, height)
        }
        present()
    }

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        surfaceReady = false
        surfaceWidth = 0
        surfaceHeight = 0
        nativePresenter?.setSurface(null, 0, 0)
        Log.i("SsalPresenter", "Surface destroyed")
    }

    private fun watchFrames(file: File) {
        val thread = HandlerThread("SsalFrameReceiver").also { it.start() }
        receiver = thread
        val worker = Handler(thread.looper)
        val watcher = object : FileObserver(cacheDir, MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                if (path == file.name) worker.post(::readFrame)
            }

            fun readFrame() {
                val record = try {
                    file.inputStream().use { it.readNBytes(73) }
                } catch (_: java.io.FileNotFoundException) {
                    return
                } catch (error: IOException) {
                    Log.w("SsalPresenter", "Frame read failed", error)
                    return
                }
                val pixels = decodeFrame(record)
                if (pixels == null) {
                    Log.w("SsalPresenter", "Rejected SSAL frame, size=${record.size}")
                    return
                }
                runOnUiThread {
                    if (observer !== this) return@runOnUiThread
                    frame.setPixels(pixels, 0, 4, 0, 0, 4, 4)
                    hasFrame = true
                    val red = pixels.count { it == Color.RED }
                    Log.i("SsalPresenter", "Received SSAL 72 bytes, 4x4 RGBA8 stride=16 RED=$red/16")
                    present()
                }
            }
        }
        observer = watcher
        watcher.startWatching()
        worker.post(watcher::readFrame)
    }

    private fun present() {
        if (!resumed || !surfaceReady || !surfaceHolder.surface.isValid) return
        val canvas = surfaceHolder.lockCanvas() ?: return
        try {
            destination.set(0, 0, canvas.width, canvas.height)
            if (hasFrame) {
                canvas.drawBitmap(frame, null, destination, paint)
            } else {
                canvas.drawColor(Color.BLACK)
            }
        } finally {
            surfaceHolder.unlockCanvasAndPost(canvas)
        }
        if (hasFrame) {
            val source = if (inbox == null) "local" else "bridge"
            Log.i("SsalPresenter", "Posted $source 4x4 frame")
        }
    }
}
