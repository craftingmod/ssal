package alyac.android.ssalsurface

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FrameRecordTest {
    @Test
    fun validatesHeaderAndConvertsRgbaToArgb() {
        val header = byteArrayOf(83, 83, 65, 76, 4, 4, 16, 1)
        val record = header + ByteArray(64) { byteArrayOf(-1, 0, 17, -128)[it % 4] }
        assertArrayEquals(IntArray(16) { 0x80ff0011.toInt() }, decodeFrame(record))
        assertNull(decodeFrame(record.copyOf(71)))
        assertNull(decodeFrame(record.copyOf(73)))
        for (index in header.indices) {
            val invalid = record.copyOf()
            invalid[index] = 0
            assertNull(decodeFrame(invalid))
        }
    }
}
