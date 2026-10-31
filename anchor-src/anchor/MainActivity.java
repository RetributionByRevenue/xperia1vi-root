package com.ghostlock.anchor;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        tv.setText("GhostLock Anchor armed.\n\n"
            + "On every boot this app re-runs the exploit via loopback adb\n"
            + "(persist.adb.tcp.port=5555) and restores KernelSU root.\n\n"
            + "Keep this app installed and never force-stop it.\n");
        tv.setPadding(40, 80, 40, 40);
        tv.setTextSize(16);
        setContentView(tv);
    }
}
