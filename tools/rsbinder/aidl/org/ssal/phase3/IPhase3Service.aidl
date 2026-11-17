package org.ssal.phase3;

import org.ssal.phase3.IPhase3Callback;

interface IPhase3Service {
    int add(int a, int b);
    String echo(String message);
    String callCallback(IPhase3Callback callback, String message);
}
