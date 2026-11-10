package dev.morphe.splitfixture;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class MainActivity extends Activity {
    public static String label() { return "BASELINE"; }
    private static native String nativeValue();

    private TextView row(LinearLayout layout, String text) {
        TextView view = new TextView(this);
        view.setTextSize(23);
        view.setText(text);
        view.setPadding(16, 12, 16, 12);
        layout.addView(view);
        return view;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(16, 24, 16, 24);
        row(layout, "Real split fixture");
        final TextView labelView = row(layout, "NOT_RUN");
        final TextView resourceView = row(layout, "RESOURCE_NOT_RUN");
        final TextView nativeView = row(layout, "JNI_NOT_RUN");
        Button button = new Button(this);
        button.setText("Show label");
        layout.addView(button);
        // Compile against Android's bootclasspath without JVM LambdaMetafactory.
        button.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                labelView.setText(label());
                try {
                    int id = getResources().getIdentifier("split_probe", "string", getPackageName());
                    resourceView.setText(id == 0 ? "RESOURCE_ID_MISSING" : getString(id));
                } catch (RuntimeException failure) {
                    resourceView.setText("RESOURCE_ERROR");
                }
                try {
                    System.loadLibrary("splitprobe");
                    nativeView.setText(nativeValue());
                } catch (LinkageError | RuntimeException failure) {
                    nativeView.setText("JNI_ERROR");
                }
            }
        });
        setContentView(layout);
    }
}
