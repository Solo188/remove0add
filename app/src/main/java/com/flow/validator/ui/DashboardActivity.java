package com.flow.validator.ui;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.flow.validator.R;
import com.flow.validator.admin.AdminReceiver;
import com.flow.validator.service.MainService;
import com.flow.validator.ui.adapter.LogAdapter;
import com.google.android.material.materialswitch.MaterialSwitch;

import java.util.ArrayList;
import java.util.List;

/**
 * DashboardActivity — SentinelNode Elite Control Center.
 *
 * <p>Panels:
 * <ol>
 *   <li><b>Protection Status</b> — MaterialSwitch that starts/stops the VPN filter.</li>
 *   <li><b>Policy Compliance</b> — live Device Owner / Admin status indicator.</li>
 *   <li><b>Latency Monitor</b> — real-time DPI overhead (target &lt;1 ms),
 *       updated every 500 ms by MainService's latency reporter thread.</li>
 *   <li><b>Filtered Events Log</b> — RecyclerView fed by MainService.EventListener.</li>
 * </ol>
 *
 * Uses {@link ActivityResultLauncher} for the VPN-permission flow (replaces
 * the deprecated {@code startActivityForResult} / {@code onActivityResult} APIs).
 */
public class DashboardActivity extends AppCompatActivity
        implements MainService.EventListener {

    // UI references
    private MaterialSwitch toggleProtection;
    private TextView       tvOwnerStatus;
    private TextView       tvLatencyValue;
    private TextView       tvLatencyStatus;
    private TextView       tvFilterCount;
    private RecyclerView   rvLogs;
    private LogAdapter     logAdapter;

    // Service binding
    private MainService mainService;
    private boolean     isBound = false;

    private final List<String> logLines = new ArrayList<>();
    private int filteredCount = 0;

    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    /**
     * ActivityResultLauncher for VPN permission dialog.
     * Must be registered before onCreate returns.
     */
    private final ActivityResultLauncher<Intent> vpnPermLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == RESULT_OK) {
                            if (mainService != null) mainService.startVpn();
                        } else {
                            // User denied — uncheck the toggle without triggering listener
                            setToggleChecked(false);
                            Toast.makeText(this, "VPN permission denied",
                                    Toast.LENGTH_SHORT).show();
                        }
                    });

    // =========================================================================
    // Lifecycle
    // =========================================================================

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dashboard);
        bindViews();
        setupRecyclerView();
        setupToggle();

        Intent svcIntent = new Intent(this, MainService.class);
        startService(svcIntent);
        bindService(svcIntent, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshOwnerStatus();
    }

    @Override
    protected void onDestroy() {
        if (isBound && mainService != null) {
            mainService.removeEventListener(this);
            unbindService(serviceConnection);
            isBound = false;
        }
        super.onDestroy();
    }

    // =========================================================================
    // View setup
    // =========================================================================

    private void bindViews() {
        toggleProtection = findViewById(R.id.toggle_protection);
        tvOwnerStatus    = findViewById(R.id.tv_owner_status);
        tvLatencyValue   = findViewById(R.id.tv_latency_value);
        tvLatencyStatus  = findViewById(R.id.tv_latency_status);
        tvFilterCount    = findViewById(R.id.tv_filter_count);
        rvLogs           = findViewById(R.id.rv_logs);
    }

    private void setupRecyclerView() {
        logAdapter = new LogAdapter(logLines);
        rvLogs.setLayoutManager(new LinearLayoutManager(this));
        rvLogs.setAdapter(logAdapter);
    }

    private void setupToggle() {
        toggleProtection.setOnCheckedChangeListener((btn, isChecked) -> {
            if (!isBound || mainService == null) {
                setToggleChecked(false);
                Toast.makeText(this, "Service not ready", Toast.LENGTH_SHORT).show();
                return;
            }
            if (isChecked) {
                requestVpnPermissionAndStart();
            } else {
                mainService.stopVpn();
            }
        });
    }

    /** Set toggle state without triggering the OnCheckedChangeListener. */
    private void setToggleChecked(boolean checked) {
        toggleProtection.setOnCheckedChangeListener(null);
        toggleProtection.setChecked(checked);
        setupToggle();
    }

    // =========================================================================
    // VPN permission flow — ActivityResultLauncher (non-deprecated)
    // =========================================================================

    private void requestVpnPermissionAndStart() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            // Need user permission — launch the system dialog
            vpnPermLauncher.launch(prepare);
        } else {
            // Already granted
            if (mainService != null) mainService.startVpn();
        }
    }

    // =========================================================================
    // Compliance indicator
    // =========================================================================

    private void refreshOwnerStatus() {
        DevicePolicyManager dpm =
                (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        boolean isOwner = dpm != null && dpm.isDeviceOwnerApp(getPackageName());
        ComponentName cn = AdminReceiver.getComponentName(this);
        boolean isAdmin  = dpm != null && dpm.isAdminActive(cn);

        if (isOwner) {
            tvOwnerStatus.setText("DEVICE OWNER — Full Compliance Active");
            tvOwnerStatus.setTextColor(0xFF3FB950);
        } else if (isAdmin) {
            tvOwnerStatus.setText("DEVICE ADMIN — Partial Compliance");
            tvOwnerStatus.setTextColor(0xFFD29922);
        } else {
            tvOwnerStatus.setText("NO ADMIN — Policy Inactive");
            tvOwnerStatus.setTextColor(0xFFFF7B72);
        }
    }

    // =========================================================================
    // MainService.EventListener callbacks (called from service threads)
    // =========================================================================

    @Override
    public void onFilteredEvent(String logLine) {
        uiHandler.post(() -> {
            filteredCount++;
            tvFilterCount.setText("Filtered: " + filteredCount);
            logLines.add(0, logLine);
            if (logLines.size() > 150) logLines.remove(logLines.size() - 1);
            logAdapter.notifyItemInserted(0);
            rvLogs.scrollToPosition(0);
        });
    }

    @Override
    public void onVpnStateChanged(boolean running) {
        uiHandler.post(() -> {
            setToggleChecked(running);
            Toast.makeText(this,
                    running ? "Protection ON" : "Protection OFF",
                    Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onLatencyUpdate(String summary) {
        uiHandler.post(() -> {
            if (tvLatencyValue == null) return;
            tvLatencyValue.setText(summary);

            double avgMs = parseAvgMs(summary);
            if (avgMs < 1.0) {
                tvLatencyStatus.setText("< 1 ms  OK");
                tvLatencyStatus.setTextColor(0xFF3FB950);
            } else if (avgMs < 5.0) {
                tvLatencyStatus.setText(String.format("%.2f ms  WARN", avgMs));
                tvLatencyStatus.setTextColor(0xFFD29922);
            } else {
                tvLatencyStatus.setText(String.format("%.2f ms  HIGH", avgMs));
                tvLatencyStatus.setTextColor(0xFFFF7B72);
            }
        });
    }

    /** Parse the avg ms value from summary string "avg 0.012 ms | peak 0.034 ms". */
    private static double parseAvgMs(String summary) {
        try {
            int start = summary.indexOf("avg ") + 4;
            int end   = summary.indexOf(" ms");
            if (start > 3 && end > start) {
                return Double.parseDouble(summary.substring(start, end).trim());
            }
        } catch (Exception ignored) {}
        return 0.0;
    }

    // =========================================================================
    // Service connection
    // =========================================================================

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mainService = ((MainService.LocalBinder) service).getService();
            isBound     = true;
            mainService.addEventListenerSafe(DashboardActivity.this);

            // Sync toggle to current VPN state
            setToggleChecked(mainService.isVpnRunning());

            // Load buffered events into log view
            List<String> existing = mainService.latestLogEvents(100);
            logLines.clear();
            logLines.addAll(existing);
            logAdapter.notifyDataSetChanged();
            filteredCount = existing.size();
            tvFilterCount.setText("Filtered: " + filteredCount);

            refreshOwnerStatus();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            mainService = null;
            isBound     = false;
        }
    };
}
