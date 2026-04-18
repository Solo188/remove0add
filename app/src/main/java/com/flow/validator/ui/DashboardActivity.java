package com.flow.validator.ui;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;
import com.flow.validator.service.ValidatorVpnService;
import com.flow.validator.R;

public class DashboardActivity extends Activity {
    private Switch dnsSwitch, httpSwitch, httpsSwitch;
    private TextView statusText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dashboard);

        dnsSwitch = findViewById(R.id.toggle_mode_dns);
        httpSwitch = findViewById(R.id.toggle_mode_http);
        httpsSwitch = findViewById(R.id.toggle_mode_https);
        statusText = findViewById(R.id.statusText);
        Button btnStart = findViewById(R.id.btnStartVpn);

        btnStart.setOnClickListener(v -> {
            Intent intent = VpnService.prepare(this);
            if (intent != null) {
                startActivityForResult(intent, 0);
            } else {
                onActivityResult(0, RESULT_OK, null);
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            Intent vpnIntent = new Intent(this, ValidatorVpnService.class);
            // Передаем настройки режимов в сервис
            vpnIntent.putExtra("dns_block", dnsSwitch.isChecked());
            vpnIntent.putExtra("http_dpi", httpSwitch.isChecked());
            vpnIntent.putExtra("https_sni", httpsSwitch.isChecked());
            
            startService(vpnIntent);
            statusText.setText("Status: Shield Active");
            Toast.makeText(this, "Sentinel Shield Started!", Toast.LENGTH_SHORT).show();
        }
    }
}
