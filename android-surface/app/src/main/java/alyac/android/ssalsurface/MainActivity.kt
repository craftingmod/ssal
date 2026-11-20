package alyac.android.ssalsurface

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.os.Bundle
import android.os.FileObserver
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import java.io.File
import java.io.IOException

class MainActivity : AppCompatActivity(), SurfaceHolder.Callback {
    private lateinit var surfaceHolder: SurfaceHolder
    private val frame = Bitmap.createBitmap(4, 4, Bitmap.Config.ARGB_8888).apply {
        eraseColor(Color.BLACK)
    }
    private val paint = Paint().apply { isFilterBitmap = false }
    private val bootBgColor = Color.rgb(0x14, 0x14, 0x16)
    private val bootTitlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(0xB8, 0xBC, 0xC4)
        textSize = 48f
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
    }
    private val bootSubPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(0x74, 0x78, 0x80)
        textSize = 28f
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
    }
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
    private var hasFrame = false
    private val touchIds = IntArray(10)
    private val touchXs = FloatArray(10)
    private val touchYs = FloatArray(10)
    private val touchPressures = FloatArray(10)
    private var activeTouch = false
    private var lastTouchDownTime = 0L
    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    nativePresenter?.sendKey(KeyEvent.KEYCODE_SLEEP, SystemClock.uptimeMillis())
                }
                Intent.ACTION_SCREEN_ON -> {
                    if (resumed) {
                        nativePresenter?.sendKey(
                            KeyEvent.KEYCODE_WAKEUP,
                            SystemClock.uptimeMillis(),
                        )
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        hideSystemBars()
        val surfaceView = findViewById<SurfaceView>(R.id.presenter_surface)
        surfaceView.setOnTouchListener { _, event -> handleTouch(event) }
        surfaceHolder = surfaceView.holder
        surfaceHolder.addCallback(this)
        val screenFilter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        registerReceiver(screenReceiver, screenFilter)
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

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            hideSystemBars()
        }
    }

    private fun hideSystemBars() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val controller = WindowCompat.getInsetsController(window, window.decorView)
        controller.systemBarsBehavior =
            WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        controller.hide(WindowInsetsCompat.Type.systemBars())
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        hideSystemBars()
        inbox?.let(::watchFrames)
        presenterSocket?.let { addr ->
            if (nativePresenter == null) {
                nativePresenter = NativePresenter(addr)
                if (surfaceReady && surfaceHolder.surface.isValid) {
                    nativePresenter?.setSurface(surfaceHolder.surface, surfaceWidth, surfaceHeight)
                }
            }
            nativePresenter?.sendKey(KeyEvent.KEYCODE_WAKEUP, SystemClock.uptimeMillis())
        }
        present()
    }

    override fun onPause() {
        cancelActiveTouch()
        resumed = false
        val closing = nativePresenter
        nativePresenter = null
        closing?.let { presenter ->
            presenter.setSurface(null, 0, 0)
            Thread { presenter.close() }.start()
        }
        observer?.stopWatching()
        observer = null
        receiver?.quitSafely()
        receiver = null
        Log.i("SsalPresenter", "Activity paused")
        super.onPause()
    }

    override fun onDestroy() {
        unregisterReceiver(screenReceiver)
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
        cancelActiveTouch()
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
        if (nativePresenter != null) return
        if (!resumed || !surfaceReady || !surfaceHolder.surface.isValid) return
        val canvas = surfaceHolder.lockCanvas() ?: return
        try {
            destination.set(0, 0, canvas.width, canvas.height)
            if (hasFrame) {
                canvas.drawBitmap(frame, null, destination, paint)
            } else {
                canvas.drawColor(bootBgColor)
                val cx = canvas.width / 2f
                val cy = canvas.height / 2f
                canvas.drawText("Guest OS 부팅 중...", cx, cy - 12f, bootTitlePaint)
                canvas.drawText("Surface 출력 대기 중", cx, cy + 36f, bootSubPaint)
            }
        } finally {
            surfaceHolder.unlockCanvasAndPost(canvas)
        }
        if (hasFrame) {
            val source = if (inbox == null) "local" else "bridge"
            Log.i("SsalPresenter", "Posted $source 4x4 frame")
        }
    }

    private fun handleTouch(event: MotionEvent): Boolean {
        val presenter = nativePresenter ?: return false
        if (!resumed || !surfaceReady) return false
        val count = event.pointerCount.coerceAtMost(touchIds.size)
        if (count <= 0) return false
        for (i in 0 until count) {
            touchIds[i] = event.getPointerId(i)
            touchXs[i] = event.getX(i)
            touchYs[i] = event.getY(i)
            touchPressures[i] = event.getPressure(i)
        }
        val masked = event.actionMasked
        activeTouch = masked != MotionEvent.ACTION_UP && masked != MotionEvent.ACTION_CANCEL
        lastTouchDownTime = event.downTime
        presenter.sendTouch(
            event.action,
            count,
            event.downTime,
            event.eventTime,
            touchIds,
            touchXs,
            touchYs,
            touchPressures,
        )
        return true
    }

    private fun cancelActiveTouch() {
        if (!activeTouch) return
        activeTouch = false
        val presenter = nativePresenter ?: return
        val now = SystemClock.uptimeMillis()
        presenter.sendTouch(
            MotionEvent.ACTION_CANCEL,
            1,
            lastTouchDownTime,
            now,
            touchIds,
            touchXs,
            touchYs,
            touchPressures,
        )
    }
}
