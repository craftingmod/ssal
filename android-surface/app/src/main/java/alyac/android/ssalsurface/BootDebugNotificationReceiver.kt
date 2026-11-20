package alyac.android.ssalsurface

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

class BootDebugNotificationReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_GUEST_BOOT_COMPLETED) {
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "POST_NOTIFICATIONS permission not granted; skipping debug notification")
            return
        }

        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "SSAL Guest Boot Debug",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Notifications when Guest ApexService::markBootCompleted is reached"
        }
        manager.createNotificationChannel(channel)

        val message = intent.getStringExtra(EXTRA_MESSAGE)
            ?: "ApexService::markBootCompleted reached"
        val launchIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val contentIntent = PendingIntent.getActivity(
            context,
            0,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("SSAL Guest Boot Completed")
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(contentIntent)
            .build()

        manager.notify(NOTIFICATION_ID, notification)
        Log.i(TAG, "Posted Guest boot debug notification: $message")
    }

    companion object {
        const val ACTION_GUEST_BOOT_COMPLETED =
            "alyac.android.ssalsurface.ACTION_GUEST_BOOT_COMPLETED"
        const val EXTRA_MESSAGE = "message"
        private const val CHANNEL_ID = "ssal_debug_boot"
        private const val NOTIFICATION_ID = 1001
        private const val TAG = "SsalBootNotify"
    }
}
