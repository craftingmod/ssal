package alyac.android.ssalsurface

internal fun decodeFrame(record: ByteArray): IntArray? {
    if (record.size != 72 || !record.copyOfRange(0, 4).contentEquals("SSAL".toByteArray()) ||
        record[4] != 4.toByte() || record[5] != 4.toByte() ||
        record[6] != 16.toByte() || record[7] != 1.toByte()
    ) return null

    return IntArray(16) { index ->
        val offset = 8 + index * 4
        val red = record[offset].toUByte().toInt()
        val green = record[offset + 1].toUByte().toInt()
        val blue = record[offset + 2].toUByte().toInt()
        val alpha = record[offset + 3].toUByte().toInt()
        (alpha shl 24) or (red shl 16) or (green shl 8) or blue
    }
}
