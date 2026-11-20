package dev.ssal.input;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.IBinder;
import android.view.InputDevice;
import android.view.InputEvent;
import android.view.MotionEvent;

import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Persistent Guest input injector reading touch packets from stdin (SOCK_SEQPACKET fd 0)
 * and forwarding them to Guest InputManagerService via IInputManager.injectInputEvent.
 */
public final class InputInjector {
    private static final int TOUCH_MAGIC = 0x53544348; // 'STCH'
    private static final int TOUCH_VERSION = 1;
    private static final int HEADER_BYTES = 32;
    private static final int POINTER_BYTES = 16;
    private static final int MAX_POINTERS = 10;
    private static final int INJECT_INPUT_EVENT_MODE_ASYNC = 0;

    public static void main(String[] args) throws Exception {
        Method getService = Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class);
        Method asInterface = Class.forName("android.hardware.input.IInputManager$Stub")
                .getMethod("asInterface", IBinder.class);

        Object inputManager = null;
        while (inputManager == null) {
            IBinder binder = (IBinder) getService.invoke(null, "input");
            if (binder != null) {
                inputManager = asInterface.invoke(null, binder);
                if (inputManager != null) {
                    break;
                }
            }
            Thread.sleep(200);
        }

        Method injectInputEvent = inputManager.getClass()
                .getMethod("injectInputEvent", InputEvent.class, int.class);

        System.out.println("GUEST_INPUT_INJECTOR_READY=PASS");
        System.out.flush();

        MotionEvent.PointerProperties[] props = new MotionEvent.PointerProperties[MAX_POINTERS];
        MotionEvent.PointerCoords[] coords = new MotionEvent.PointerCoords[MAX_POINTERS];
        for (int i = 0; i < MAX_POINTERS; i++) {
            props[i] = new MotionEvent.PointerProperties();
            props[i].toolType = MotionEvent.TOOL_TYPE_FINGER;
            coords[i] = new MotionEvent.PointerCoords();
            coords[i].size = 1.0f;
        }

        byte[] buf = new byte[HEADER_BYTES + MAX_POINTERS * POINTER_BYTES];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);

        try (LocalSocket sock = new LocalSocket(LocalSocket.SOCKET_STREAM)) {
            sock.connect(new LocalSocketAddress(
                    "/dev/socket/ssal-input.sock",
                    LocalSocketAddress.Namespace.FILESYSTEM));
            System.out.println("GUEST_INPUT_INJECTOR_CONNECTED=PASS");
            System.out.flush();
            DataInputStream in = new DataInputStream(sock.getInputStream());
            while (true) {
                try {
                    in.readFully(buf, 0, HEADER_BYTES);
                } catch (IOException e) {
                    System.err.println("GUEST_INPUT_INJECTOR_READ_ERR=" + e.getMessage());
                    break;
                }

                bb.position(0);
                int magic = bb.getInt();
                int version = bb.getInt();
                int action = bb.getInt();
                int pointerCount = bb.getInt();
                long downTime = bb.getLong();
                long eventTime = bb.getLong();

                if (magic != TOUCH_MAGIC || version != TOUCH_VERSION ||
                        pointerCount <= 0 || pointerCount > MAX_POINTERS) {
                    System.err.println("GUEST_INPUT_INJECTOR_BAD_HDR magic=" + magic + " count=" + pointerCount);
                    break;
                }
                try {
                    in.readFully(buf, HEADER_BYTES, pointerCount * POINTER_BYTES);
                } catch (IOException e) {
                    System.err.println("GUEST_INPUT_INJECTOR_READ_ERR=" + e.getMessage());
                    break;
                }

                for (int i = 0; i < pointerCount; i++) {
                    props[i].id = bb.getInt();
                    props[i].toolType = MotionEvent.TOOL_TYPE_FINGER;
                    coords[i].x = bb.getFloat();
                    coords[i].y = bb.getFloat();
                    coords[i].pressure = bb.getFloat();
                }

                MotionEvent ev = MotionEvent.obtain(
                        downTime,
                        eventTime,
                        action,
                        pointerCount,
                        props,
                        coords,
                        0,
                        0,
                        1.0f,
                        1.0f,
                        0,
                        0,
                        InputDevice.SOURCE_TOUCHSCREEN,
                        0
                );
                try {
                    injectInputEvent.invoke(inputManager, ev, INJECT_INPUT_EVENT_MODE_ASYNC);
                } finally {
                    ev.recycle();
                }
            }
        }
    }
}
