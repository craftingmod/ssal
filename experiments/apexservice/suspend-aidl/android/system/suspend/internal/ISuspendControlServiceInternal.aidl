/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.system.suspend.internal;

import android.system.suspend.internal.SuspendInfo;
import android.system.suspend.internal.WakeLockInfo;
import android.system.suspend.internal.WakeupInfo;

/**
 * Interface exposed by the suspend hal that allows framework to toggle the suspend loop and
 * monitor native wakelocks.
 * @hide
 */
interface ISuspendControlServiceInternal {
    /**
     * Starts automatic system suspension.
     *
     * @param token token registering automatic system suspension.
     * When all registered tokens die automatic system suspension is disabled.
     * @return true on success, false otherwise.
     */
    boolean enableAutosuspend(IBinder token);

    /**
     * Suspends the system even if there are wakelocks being held.
     */
    boolean forceSuspend();

    /**
     * Returns a list of wake lock stats.
     */
    WakeLockInfo[] getWakeLockStats();

    /**
     * Returns a list of wake lock stats. Fields not selected with the
     * bit mask are in an undefined state (see WAKE_LOCK_INFO_* below).
     */
    WakeLockInfo[] getWakeLockStatsFiltered(int wakeLockInfoFieldBitMask);

    /**
     * Returns a list of wakeup stats.
     */
    WakeupInfo[] getWakeupStats();

    /**
     * Returns stats related to suspend.
     */
    SuspendInfo getSuspendStats();

    /**
     * Used to select fields from WakeLockInfo that getWakeLockStats should return.
     * This is in addition to the name of the wake lock, which is always returned.
     */
    const int WAKE_LOCK_INFO_ACTIVE_COUNT = 1 << 0;
    const int WAKE_LOCK_INFO_LAST_CHANGE = 1 << 1;
    const int WAKE_LOCK_INFO_MAX_TIME = 1 << 2;
    const int WAKE_LOCK_INFO_TOTAL_TIME = 1 << 3;
    const int WAKE_LOCK_INFO_IS_ACTIVE = 1 << 4;
    const int WAKE_LOCK_INFO_ACTIVE_TIME = 1 << 5;
    const int WAKE_LOCK_INFO_IS_KERNEL_WAKELOCK = 1 << 6;

    // Specific to Native wake locks.
    const int WAKE_LOCK_INFO_PID = 1 << 7;

    // Specific to Kernel wake locks.
    const int WAKE_LOCK_INFO_EVENT_COUNT = 1 << 8;
    const int WAKE_LOCK_INFO_EXPIRE_COUNT = 1 << 9;
    const int WAKE_LOCK_INFO_PREVENT_SUSPEND_TIME = 1 << 10;
    const int WAKE_LOCK_INFO_WAKEUP_COUNT = 1 << 11;

    const int WAKE_LOCK_INFO_ALL_FIELDS = (1 << 12) - 1;
}
