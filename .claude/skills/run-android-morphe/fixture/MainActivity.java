package dev.morphe.fixture;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Self-authored offline fixture. No network, files, accounts or native code. */
public final class MainActivity extends Activity {
    public static String label() { return "BASELINE"; }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        final TextView result = new TextView(this);
        result.setText("Press the button");
        result.setTextSize(28);
        Button button = new Button(this);
        button.setText("Show label");
        button.setOnClickListener(new android.view.View.OnClickListener() {
            @Override public void onClick(android.view.View view) { result.setText(label()); }
        });
        layout.addView(button);
        layout.addView(result);
        setContentView(layout);
    }
}
