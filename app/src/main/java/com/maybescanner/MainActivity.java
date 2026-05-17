package com.maybescanner;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.animation.LayoutTransition;
import android.os.BatteryManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.*;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class MainActivity extends Activity {
    public static final String ACTION_QUICK_SCAN = "com.maybescanner.action.QUICK_SCAN";
    private static final int BLUE = Color.rgb(55, 212, 255);
    private static final int BG = Color.rgb(7, 16, 24);
    private static final int PANEL = Color.rgb(13, 28, 39);
    private static final int FIELD = Color.rgb(9, 20, 29);
    private static final int MUTED = Color.rgb(140, 161, 178);

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final AtomicBoolean stop = new AtomicBoolean(false);
    private final AtomicBoolean renderQueued = new AtomicBoolean(false);
    private final AtomicInteger checkedTargets = new AtomicInteger(0);
    private final List<Result> allResults = Collections.synchronizedList(new ArrayList<>());
    private ExecutorService executor;

    private LinearLayout resultList;
    private LinearLayout targetChipPreview, sniChipPreview;
    private LinearLayout analyticsPanel;
    private ScrollView mainScroll;
    private View targetAnchor, liveAnchor, vaultAnchor;
    private ProgressBar progress;
    private TextView status, metrics, bestView, countersView, logView, networkBanner;
    private TextView presetSummaryView;
    private EditText targetsInput, snisInput, totalInput, batchInput, threadsInput, timeoutInput;
    private EditText communitySampleInput, akamaiSampleInput, cloudfrontSampleInput, fastlySampleInput, cloudflareSampleInput, otherCdnSampleInput;
    private EditText portsInput, pathInput, maxLatencyInput, resultLimitInput, cdnFilterInput, certFilterInput, sniFilterInput, minQualityInput;
    private CheckBox multiSni, filterWorking, filterSni, bestPerIp, hideNoisyLogs, requireHttp, requireKnownCdn, requireTls13;
    private CheckBox stepTcp, stepTls, stepHttp, stepVerify;
    private Spinner profileSpinner, workflowSpinner, sortSpinner, presetSpinner, exportSpinner, vaultModeSpinner, visualModeSpinner;
    private Button startButton, stopButton, copyButton, copyCsvButton, exportButton, clearButton, applyPresetButton, appendPresetButton, helpButton;
    private Button tabTargetButton, tabLiveButton, tabVaultButton;
    private int totalTargets;
    private long scanStartedAt;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        buildUi();
        loadDefaults();
        maybeShowOnboarding();
        if (ACTION_QUICK_SCAN.equals(getIntent().getAction())) {
            ui.postDelayed(this::startScan, 450);
        }
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        mainScroll = scroll;
        LinearLayout root = column();
        root.setPadding(dp(14), dp(14), dp(14), dp(22));
        root.setBackground(new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.rgb(5, 14, 23), Color.rgb(8, 28, 38), Color.rgb(15, 18, 34)}));
        scroll.addView(root);

        root.addView(text("MaybeScanner", 27, Color.WHITE, true));
        root.addView(text("Standalone edge, SNI, CIDR, TCP, TLS, HTTP and CDN scanner", 13, MUTED, false));
        status = pill("Ready");
        root.addView(status);
        networkBanner = pill(networkContextLine());
        root.addView(networkBanner);
        root.addView(infoCard("Presets included", "Community edge IPs, their /24 CIDRs, SNI hosts, Akamai, CloudFront, Fastly, and conventional CDN/cloud ranges are bundled for one-tap scan setup."));
        root.addView(infoCard("Edge IP = entry server", "Targets are candidate CDN/edge endpoints. SNI controls which hostname is presented during TLS."));
        helpButton = button("Guide & parameter help", Color.rgb(23, 46, 63), Color.WHITE);
        root.addView(helpButton);
        LinearLayout tabs = row();
        tabTargetButton = button("Target Setup", Color.rgb(21, 45, 62), Color.WHITE);
        tabLiveButton = button("Live Terminal", Color.rgb(21, 45, 62), Color.WHITE);
        tabVaultButton = button("Edge Vault", Color.rgb(21, 45, 62), Color.WHITE);
        tabs.addView(tabTargetButton, weight());
        tabs.addView(tabLiveButton, weight());
        tabs.addView(tabVaultButton, weight());
        root.addView(tabs);

        LinearLayout quick = row();
        startButton = button("Start", BLUE, Color.rgb(2, 18, 24));
        stopButton = button("Stop", Color.rgb(255, 102, 122), Color.WHITE);
        clearButton = button("Clear", Color.rgb(34, 51, 66), Color.WHITE);
        stopButton.setEnabled(false);
        quick.addView(startButton, weight());
        quick.addView(stopButton, weight());
        quick.addView(clearButton, weight());
        root.addView(quick);

        targetAnchor = section("Target Setup");
        root.addView(targetAnchor);
        targetsInput = area("Targets: domains, IPv4, CIDR, ranges");
        snisInput = area("SNI hosts");
        LinearLayout presetRow = row();
        presetSpinner = spinner(new String[]{"Community defaults", "Akamai", "AWS CloudFront", "Fastly", "Cloudflare", "Other CDNs", "Everything bundled"});
        presetRow.addView(box("Preset corpus", presetSpinner), weight());
        root.addView(presetRow);
        LinearLayout presetButtons = row();
        applyPresetButton = button("Replace with preset", Color.rgb(34, 51, 66), Color.WHITE);
        appendPresetButton = button("Append preset", Color.rgb(34, 51, 66), Color.WHITE);
        presetButtons.addView(applyPresetButton, weight());
        presetButtons.addView(appendPresetButton, weight());
        root.addView(presetButtons);
        LinearLayout presetCards1 = row();
        presetCards1.addView(presetCard("Akamai", "AS20940 + 184.x", 1), weight());
        presetCards1.addView(presetCard("CloudFront", "AWS edge ranges", 2), weight());
        root.addView(presetCards1);
        LinearLayout presetCards2 = row();
        presetCards2.addView(presetCard("Fastly", "AS54113", 3), weight());
        presetCards2.addView(presetCard("Cloudflare", "official edge ranges", 4), weight());
        root.addView(presetCards2);
        LinearLayout presetCards3 = row();
        presetCards3.addView(presetCard("Other CDNs", "GitHub, Azure, Google, Bunny", 5), weight());
        presetCards3.addView(presetCard("All corpora", "Community + providers", 6), weight());
        root.addView(presetCards3);
        presetSummaryView = glassText("Preset corpora are merged with user IPs/SNIs and deduplicated before scanning.");
        root.addView(presetSummaryView);
        root.addView(section("Targets"));
        root.addView(infoCard("Custom ranges are welcome", "Paste IPs, CIDRs like 151.101.0.0/16, or ranges like 184.24.77.5-184.24.77.42. Preset cards append, so you can choose multiple provider corpora."));
        root.addView(targetsInput);
        targetChipPreview = chipPanel();
        root.addView(targetChipPreview);
        root.addView(section("SNI Hosts"));
        root.addView(snisInput);
        sniChipPreview = chipPanel();
        root.addView(sniChipPreview);

        LinearLayout row1 = row();
        profileSpinner = spinner(new String[]{"Quick TCP", "Standard TLS", "Deep HTTP + SNI", "Verify CDN edge"});
        workflowSpinner = spinner(new String[]{"Single selected profile", "Auto multi-step ladder", "Manual selected steps"});
        sortSpinner = spinner(new String[]{"Newest", "Latency", "Score", "CDN", "SNI", "HTTP first", "TLS first"});
        row1.addView(box("Profile", profileSpinner), weight());
        row1.addView(box("Workflow", workflowSpinner), weight());
        root.addView(row1);
        root.addView(box("Sort", sortSpinner));
        root.addView(infoCard("Multi-step scans", "Auto ladder runs TCP, then TLS, then HTTP/SNI, then CDN verification. Manual mode runs only the checked steps below."));
        LinearLayout stepRow1 = row();
        stepTcp = check("Step 1 TCP");
        stepTls = check("Step 2 TLS");
        stepHttp = check("Step 3 HTTP/SNI");
        stepVerify = check("Step 4 Verify");
        stepTcp.setChecked(true);
        stepTls.setChecked(true);
        stepHttp.setChecked(true);
        stepVerify.setChecked(true);
        stepRow1.addView(stepTcp, weight());
        stepRow1.addView(stepTls, weight());
        root.addView(stepRow1);
        LinearLayout stepRow2 = row();
        stepRow2.addView(stepHttp, weight());
        stepRow2.addView(stepVerify, weight());
        root.addView(stepRow2);

        root.addView(infoCard("Performance modes", "Choose a comfort mode, then expand into the numbers below if you want exact control. These are presets, not caps."));
        LinearLayout modeRow = row();
        modeRow.addView(modeButton("Battery Saver", "16 / 2000 / 2500", 16, 2000, 2500), weight());
        modeRow.addView(modeButton("Balanced", "64 / 12000 / 3000", 64, 12000, 3000), weight());
        modeRow.addView(modeButton("Aggressive", "256 / 72000 / 5000", 256, 72000, 5000), weight());
        root.addView(modeRow);

        LinearLayout row2 = row();
        totalInput = input("72000", true);
        batchInput = input("12000", true);
        threadsInput = input("64", true);
        timeoutInput = input("3000", true);
        row2.addView(box("Total cap", totalInput), weight());
        row2.addView(box("Batch", batchInput), weight());
        root.addView(row2);
        LinearLayout row3 = row();
        row3.addView(box("Threads", threadsInput), weight());
        row3.addView(box("Timeout ms", timeoutInput), weight());
        root.addView(row3);
        root.addView(infoCard("Per-source sampling", "Set how many tokens/CIDRs to load from each source. Use 0 for all. Total cap still controls the final expanded scan sample."));
        LinearLayout sourceRow1 = row();
        communitySampleInput = input("0", true);
        akamaiSampleInput = input("0", true);
        cloudfrontSampleInput = input("0", true);
        sourceRow1.addView(box("Community", communitySampleInput), weight());
        sourceRow1.addView(box("Akamai", akamaiSampleInput), weight());
        sourceRow1.addView(box("CloudFront", cloudfrontSampleInput), weight());
        root.addView(sourceRow1);
        LinearLayout sourceRow2 = row();
        fastlySampleInput = input("0", true);
        cloudflareSampleInput = input("0", true);
        otherCdnSampleInput = input("0", true);
        sourceRow2.addView(box("Fastly", fastlySampleInput), weight());
        sourceRow2.addView(box("Cloudflare", cloudflareSampleInput), weight());
        sourceRow2.addView(box("Other CDNs", otherCdnSampleInput), weight());
        root.addView(sourceRow2);

        LinearLayout row4 = row();
        portsInput = input("443", false);
        pathInput = input("/", false);
        row4.addView(box("Ports", portsInput), weight());
        row4.addView(box("HTTP path", pathInput), weight());
        root.addView(row4);

        multiSni = check("All SNI hosts");
        filterWorking = check("Working only");
        filterSni = check("TLS/HTTP only");
        bestPerIp = check("Best per IP");
        hideNoisyLogs = check("Quiet logs");
        requireHttp = check("HTTP only");
        requireKnownCdn = check("Known CDN only");
        requireTls13 = check("TLS 1.3 only");
        filterWorking.setChecked(true);
        bestPerIp.setChecked(true);
        LinearLayout checks1 = row();
        checks1.addView(multiSni, weight());
        checks1.addView(filterWorking, weight());
        root.addView(checks1);
        LinearLayout checks2 = row();
        checks2.addView(filterSni, weight());
        checks2.addView(bestPerIp, weight());
        root.addView(checks2);
        LinearLayout checks3 = row();
        checks3.addView(requireHttp, weight());
        checks3.addView(requireKnownCdn, weight());
        root.addView(checks3);
        LinearLayout checks4 = row();
        checks4.addView(requireTls13, weight());
        checks4.addView(hideNoisyLogs, weight());
        root.addView(checks4);

        LinearLayout row5 = row();
        maxLatencyInput = input("", true); maxLatencyInput.setHint("Max latency");
        resultLimitInput = input("250", true);
        row5.addView(box("Max latency ms", maxLatencyInput), weight());
        row5.addView(box("Result limit", resultLimitInput), weight());
        root.addView(row5);
        LinearLayout row6 = row();
        cdnFilterInput = input("", false); cdnFilterInput.setHint("akamai, fastly...");
        certFilterInput = input("", false); certFilterInput.setHint("CN/O/cert contains");
        row6.addView(box("CDN filter", cdnFilterInput), weight());
        row6.addView(box("Cert filter", certFilterInput), weight());
        root.addView(row6);
        LinearLayout row7 = row();
        sniFilterInput = input("", false); sniFilterInput.setHint("SNI contains");
        minQualityInput = input("", true); minQualityInput.setHint("Min quality");
        row7.addView(box("SNI filter", sniFilterInput), weight());
        row7.addView(box("Min quality", minQualityInput), weight());
        root.addView(row7);

        liveAnchor = section("Live Terminal");
        root.addView(liveAnchor);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        root.addView(progress);
        metrics = text("0 / 0 | TCP 0 | TLS 0 | HTTP 0 | Q 0", 13, Color.WHITE, false);
        countersView = text("Down 0 | timeout 0 | reset 0 | cert 0 | DNS 0 | " + resourceLine(), 12, MUTED, false);
        bestView = panelText("Best result will appear here");
        root.addView(metrics);
        root.addView(countersView);
        root.addView(bestView);
        analyticsPanel = column();
        analyticsPanel.setLayoutTransition(new LayoutTransition());
        analyticsPanel.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(105, 255, 255, 255)));
        analyticsPanel.setPadding(dp(12), dp(10), dp(12), dp(12));
        setOuterMargin(analyticsPanel, 0, dp(8), 0, dp(8));
        root.addView(analyticsPanel);

        LinearLayout buttons = row();
        copyButton = button("Copy filtered", Color.rgb(34, 51, 66), Color.WHITE);
        copyCsvButton = button("Copy filtered CSV", Color.rgb(34, 51, 66), Color.WHITE);
        exportButton = button("Export JSON", Color.rgb(34, 51, 66), Color.WHITE);
        buttons.addView(copyButton, weight());
        buttons.addView(copyCsvButton, weight());
        buttons.addView(exportButton, weight());
        root.addView(buttons);
        LinearLayout exportRow = row();
        exportSpinner = spinner(new String[]{"Line-separated IPs", "Comma-separated IPs", "IP SNI pairs", "CSV rows", "JSON"});
        exportRow.addView(box("Clipboard format", exportSpinner), weight());
        root.addView(exportRow);

        vaultAnchor = section("Edge Vault");
        root.addView(vaultAnchor);
        vaultModeSpinner = spinner(new String[]{"List cards", "Heatmap overview"});
        root.addView(box("Vault view", vaultModeSpinner));
        visualModeSpinner = spinner(new String[]{"Glass comfort", "High contrast", "Compact analyst"});
        root.addView(box("Visual mode", visualModeSpinner));
        resultList = column();
        resultList.setLayoutTransition(new LayoutTransition());
        root.addView(resultList);
        root.addView(section("Logs"));
        logView = text("", 12, MUTED, false);
        logView.setTypeface(Typeface.MONOSPACE);
        root.addView(logView);

        startButton.setOnClickListener(v -> startScan());
        stopButton.setOnClickListener(v -> stop.set(true));
        clearButton.setOnClickListener(v -> clearResults());
        helpButton.setOnClickListener(v -> showGuide());
        tabTargetButton.setOnClickListener(v -> scrollTo(targetAnchor));
        tabLiveButton.setOnClickListener(v -> scrollTo(liveAnchor));
        tabVaultButton.setOnClickListener(v -> scrollTo(vaultAnchor));
        applyPresetButton.setOnClickListener(v -> applyPreset(false));
        appendPresetButton.setOnClickListener(v -> applyPreset(true));
        copyButton.setOnClickListener(v -> copySelectedFormat());
        copyCsvButton.setOnClickListener(v -> copyWorking(true));
        exportButton.setOnClickListener(v -> exportJson());
        View.OnClickListener refresh = v -> renderResults();
        filterWorking.setOnClickListener(refresh);
        filterSni.setOnClickListener(refresh);
        bestPerIp.setOnClickListener(refresh);
        requireHttp.setOnClickListener(refresh);
        requireKnownCdn.setOnClickListener(refresh);
        requireTls13.setOnClickListener(refresh);
        sortSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { renderResults(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        vaultModeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) { renderResults(); }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        visualModeSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                renderResults();
                renderTokenPreviews();
            }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });
        targetsInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        snisInput.addTextChangedListener(simpleWatcher(this::renderTokenPreviews));
        setContentView(scroll);
        applyAccessibilityLabels();
        updateAnalytics(Collections.emptyList());
        renderTokenPreviews();
    }

    private String networkContextLine() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (cm == null) return "Network context unavailable";
            Network network = cm.getActiveNetwork();
            if (network == null) return "Offline | scanner waiting for a network";
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps == null) return "Connected | network capabilities unknown";
            String transport;
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transport = "Wi-Fi";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transport = "Cellular";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transport = "Ethernet";
            else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transport = "VPN";
            else transport = "Network";
            String metered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ? "unmetered" : "metered";
            String internet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? "validated" : "checking";
            return "Connected via " + transport + " | " + metered + " | " + internet;
        } catch (Exception ignored) {
            return "Network context unavailable";
        }
    }

    private Button presetCard(String title, String subtitle, int presetIndex) {
        Button b = button(title + "\n" + subtitle, Color.rgb(16, 38, 52), Color.WHITE);
        b.setOnClickListener(v -> {
            presetSpinner.setSelection(presetIndex);
            applyPreset(true);
        });
        b.setContentDescription(title + " preset card. " + subtitle + ". Adds these targets and SNI hosts.");
        return b;
    }

    private Button modeButton(String title, String subtitle, int threads, int batch, int timeout) {
        Button b = button(title + "\n" + subtitle, Color.rgb(16, 38, 52), Color.WHITE);
        b.setOnClickListener(v -> {
            threadsInput.setText(String.valueOf(threads));
            batchInput.setText(String.valueOf(batch));
            timeoutInput.setText(String.valueOf(timeout));
            toast(title + " values applied. You can still edit them.");
        });
        b.setContentDescription(title + " performance preset: threads, batch, timeout " + subtitle);
        return b;
    }

    private android.text.TextWatcher simpleWatcher(Runnable afterChange) {
        return new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(android.text.Editable s) { afterChange.run(); }
        };
    }

    private LinearLayout chipPanel() {
        LinearLayout panel = column();
        panel.setPadding(dp(8), dp(6), dp(8), dp(6));
        panel.setBackground(glassBg(Color.rgb(9, 23, 34), Color.argb(80, 255, 255, 255)));
        setOuterMargin(panel, 0, dp(6), 0, dp(6));
        panel.setLayoutTransition(new LayoutTransition());
        return panel;
    }

    private void renderTokenPreviews() {
        if (targetChipPreview == null || sniChipPreview == null || targetsInput == null || snisInput == null) return;
        renderChips(targetChipPreview, "Validated targets", lines(targetsInput.getText().toString()), true);
        renderChips(sniChipPreview, "Validated SNI hosts", lines(snisInput.getText().toString()), false);
    }

    private void renderChips(LinearLayout panel, String title, List<String> values, boolean targets) {
        panel.removeAllViews();
        int valid = 0;
        for (String value : values) if (targets ? validTargetToken(value) : validDomainToken(value)) valid++;
        panel.addView(text(title + ": " + valid + "/" + values.size() + " valid", 11, MUTED, true));
        LinearLayout row = row();
        row.setGravity(Gravity.START);
        int shown = Math.min(values.size(), 12);
        for (int i = 0; i < shown; i++) {
            String token = values.get(i);
            boolean ok = targets ? validTargetToken(token) : validDomainToken(token);
            row.addView(chip(token, ok), smallChipLp());
        }
        if (values.size() > shown) row.addView(chip("+" + (values.size() - shown) + " more", true), smallChipLp());
        if (values.isEmpty()) row.addView(chip(targets ? "Paste IPs, CIDRs, ranges, domains" : "Paste hostnames for TLS SNI", true), smallChipLp());
        panel.addView(row);
    }

    private TextView chip(String label, boolean ok) {
        TextView v = text(trim(label, 22), 11, Color.WHITE, false);
        int fill = ok ? Color.rgb(11, 58, 46) : Color.rgb(74, 26, 37);
        int stroke = ok ? Color.argb(150, 66, 230, 170) : Color.argb(170, 255, 120, 140);
        v.setBackground(glassBg(fill, stroke));
        v.setPadding(dp(8), dp(5), dp(8), dp(5));
        v.setContentDescription((ok ? "Valid token " : "Invalid token ") + label);
        return v;
    }

    private LinearLayout.LayoutParams smallChipLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.setMargins(0, dp(3), dp(5), dp(3));
        return lp;
    }

    private static boolean validTargetToken(String value) {
        if (value == null || value.trim().isEmpty()) return false;
        String v = value.trim();
        if (v.contains("-")) {
            String[] p = v.split("-", 2);
            return p.length == 2 && isIp(p[0]) && isIp(p[1]);
        }
        if (v.contains("/")) {
            String[] p = v.split("/", 2);
            try {
                int prefix = Integer.parseInt(p[1]);
                return p.length == 2 && isIp(p[0]) && prefix >= 0 && prefix <= (p[0].contains(":") ? 128 : 32);
            } catch (Exception ignored) { return false; }
        }
        return isIp(v) || validDomainToken(v);
    }

    private static boolean validDomainToken(String value) {
        return value != null && value.matches("(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$");
    }

    private void scrollTo(View anchor) {
        if (mainScroll == null || anchor == null) return;
        mainScroll.post(() -> mainScroll.smoothScrollTo(0, anchor.getTop()));
    }

    private void maybeShowOnboarding() {
        SharedPreferences prefs = getSharedPreferences("maybescanner", MODE_PRIVATE);
        if (prefs.getBoolean("onboarded_v2", false)) return;
        prefs.edit().putBoolean("onboarded_v2", true).apply();
        ui.postDelayed(() -> new AlertDialog.Builder(this)
                .setTitle("Welcome to MaybeScanner")
                .setMessage("1. Pick target corpora: Akamai, CloudFront, Fastly, or all bundled presets.\n\n" +
                        "2. Pick SNI hosts: SNI is the hostname used during TLS. Presets include useful defaults, and your custom hosts are merged in.\n\n" +
                        "3. Scan and filter: choose a single profile, Auto multi-step ladder, or Manual selected steps. Live Terminal shows progress; Edge Vault lets you sort by score, filter by SNI/cert/CDN/latency, and copy only visible rows.")
                .setPositiveButton("Start setup", (d, which) -> scrollTo(targetAnchor))
                .setNegativeButton("Guide", (d, which) -> showGuide())
                .show(), 550);
    }

    private void applyAccessibilityLabels() {
        targetsInput.setContentDescription("Targets input. Add domains, IP addresses, or CIDR ranges.");
        snisInput.setContentDescription("SNI hosts input. Add one or more TLS hostnames.");
        startButton.setContentDescription("Start scan with the selected targets, SNI hosts, profile, filters, and performance values.");
        stopButton.setContentDescription("Stop the active scan.");
        copyButton.setContentDescription("Copy filtered results using the selected clipboard format.");
        progress.setContentDescription("Scan progress");
        workflowSpinner.setContentDescription("Scan workflow. Choose single profile, automatic multi-step ladder, or manual selected steps.");
        visualModeSpinner.setContentDescription("Visual mode. Glass comfort is spacious, High contrast increases readability, Compact analyst shows denser result cards.");
    }

    private void showGuide() {
        new AlertDialog.Builder(this)
                .setTitle("MaybeScanner guide")
                .setMessage(
                        "What to scan\n" +
                        "Targets are IPs, domains, or CIDR ranges. Presets add bundled Akamai, AWS CloudFront, Fastly, other cloud, and community edge corpora.\n\n" +
                        "SNI hosts\n" +
                        "SNI is the hostname sent during TLS. Use preset SNIs or add your own domains. Enable All SNI hosts for deeper matching; leave it off for faster scans.\n\n" +
                        "Profiles\n" +
                        "Quick TCP checks reachability. Standard TLS verifies TLS. Deep HTTP + SNI adds HTTP HEAD checks. Verify CDN edge favors confirmed working CDN-like endpoints.\n\n" +
                        "Workflows\n" +
                        "Single runs one selected profile. Auto multi-step ladder runs TCP, then TLS, then HTTP/SNI, then CDN verification. Manual selected steps runs only the checked stages, useful when you want a focused pass without changing presets.\n\n" +
                        "Visual modes\n" +
                        "Glass comfort is the default card layout. High contrast avoids color-only status cues and increases card opacity. Compact analyst reduces spacing so more edges fit on screen.\n\n" +
                        "Performance parameters\n" +
                        "Total cap limits expanded CIDRs. Batch controls how many targets run per wave. Threads controls parallel sockets. Timeout ms controls how long each connect/TLS/HTTP attempt can wait.\n\n" +
                        "Filtering and sorting\n" +
                        "Use Working only, TLS/HTTP only, HTTP only, Known CDN only, TLS 1.3 only, SNI filter, CDN filter, certificate filter, max latency, and min score. Sort by Score to surface the strongest candidates.\n\n" +
                        "Copy and export\n" +
                        "Copy filtered uses exactly the rows currently visible after filters and sort. Choose line-separated IPs, comma-separated IPs, IP SNI pairs, CSV, or JSON.")
                .setPositiveButton("Got it", null)
                .show();
    }

    private void loadDefaults() {
        LinkedHashSet<String> targets = new LinkedHashSet<>(loadAsset("default_targets.txt"));
        targets.addAll(loadAsset("default_edges_extra.txt"));
        targets.addAll(loadAsset("scan-corpora/community-edge-ips.txt"));
        targets.addAll(loadAsset("scan-corpora/community-edge-cidrs-24.txt"));
        targetsInput.setText(joinLines(targets));
        LinkedHashSet<String> snis = new LinkedHashSet<>(loadAsset("default_snis.txt"));
        snis.addAll(loadAsset("scan-corpora/community-sni-hosts.txt"));
        snisInput.setText(joinLines(snis));
    }

    private void applyPreset(boolean append) {
        Preset preset = loadSelectedPreset();
        if (append) {
            LinkedHashSet<String> targets = new LinkedHashSet<>(lines(targetsInput.getText().toString()));
            targets.addAll(preset.targets);
            targetsInput.setText(joinLines(targets));
            LinkedHashSet<String> snis = new LinkedHashSet<>(lines(snisInput.getText().toString()));
            snis.addAll(preset.snis);
            snisInput.setText(joinLines(snis));
        } else {
            targetsInput.setText(joinLines(preset.targets));
            snisInput.setText(joinLines(preset.snis));
        }
        String summary = preset.name + ": " + preset.targets.size() + " target tokens, " + preset.snis.size() +
                " SNI | " + preset.detail;
        presetSummaryView.setText(summary);
        toast((append ? "Appended " : "Loaded ") + summary);
    }

    private Preset loadSelectedPreset() {
        int selected = presetSpinner.getSelectedItemPosition();
        Preset p = new Preset(String.valueOf(presetSpinner.getSelectedItem()));
        p.snis.addAll(loadAsset("default_snis.txt"));
        p.snis.addAll(loadAsset("scan-corpora/community-sni-hosts.txt"));
        if (selected == 0 || selected == 6) {
            int count = intValue(communitySampleInput, 0);
            addAll(p, "app defaults", sampleSource(loadAsset("default_targets.txt"), count));
            addAll(p, "extra edges", sampleSource(loadAsset("default_edges_extra.txt"), count));
            addAll(p, "community IPs", sampleSource(loadAsset("scan-corpora/community-edge-ips.txt"), count));
            addAll(p, "community /24 CIDRs", sampleSource(loadAsset("scan-corpora/community-edge-cidrs-24.txt"), count));
        }
        if (selected == 1 || selected == 6) {
            int count = intValue(akamaiSampleInput, 0);
            addAll(p, "Akamai AS20940", sampleSource(loadAssetTokens("scan-corpora/akamai-AS20940.json"), count));
            addAll(p, "Akamai 184.x hosts", sampleSource(loadAsset("scan-corpora/akamai-hosts-184x.txt"), count));
            addRelevantSni(p.snis, "akamai");
        }
        if (selected == 2 || selected == 6) {
            addAll(p, "AWS CloudFront", sampleSource(loadAssetTokens("scan-corpora/aws-cloudfront-ranges.txt"), intValue(cloudfrontSampleInput, 0)));
            addRelevantSni(p.snis, "aws");
            addRelevantSni(p.snis, "cloudfront");
        }
        if (selected == 3 || selected == 6) {
            addAll(p, "Fastly AS54113", sampleSource(loadAssetTokens("scan-corpora/fastly-AS54113.json"), intValue(fastlySampleInput, 0)));
            addRelevantSni(p.snis, "fastly");
        }
        if (selected == 4 || selected == 6) {
            addAll(p, "Cloudflare", sampleSource(loadAssetTokens("scan-corpora/cloudflare-ranges.txt"), intValue(cloudflareSampleInput, 0)));
            addRelevantSni(p.snis, "cloudflare");
        }
        if (selected == 5 || selected == 6) {
            int count = intValue(otherCdnSampleInput, 0);
            addAll(p, "GitHub Pages", sampleSource(loadAssetTokens("scan-corpora/github-pages-ranges.txt"), count));
            addAll(p, "Azure Front Door", sampleSource(loadAssetTokens("scan-corpora/azure-frontdoor-ranges.txt"), count));
            addAll(p, "Google CDN", sampleSource(loadAssetTokens("scan-corpora/google-cdn-ranges.txt"), count));
            addAll(p, "Bunny CDN", sampleSource(loadAssetTokens("scan-corpora/bunny-ranges.txt"), count));
            addAll(p, "StackPath/Edgio", sampleSource(loadAssetTokens("scan-corpora/stackpath-edgio-ranges.txt"), count));
            addAll(p, "conventional CDN/cloud ranges", sampleSource(loadAssetTokens("scan-corpora/other-cloud-ranges.txt"), count));
            addRelevantSni(p.snis, "cloudflare");
            addRelevantSni(p.snis, "mapbox");
        }
        return p;
    }

    private LinkedHashSet<String> sampleSource(Collection<String> values, int count) {
        ArrayList<String> list = new ArrayList<>(values);
        Collections.shuffle(list, new Random(System.nanoTime()));
        LinkedHashSet<String> out = new LinkedHashSet<>();
        int limit = count <= 0 ? list.size() : Math.min(count, list.size());
        for (int i = 0; i < limit; i++) out.add(list.get(i));
        return out;
    }

    private void addAll(Preset preset, String label, Collection<String> values) {
        int before = preset.targets.size();
        preset.targets.addAll(values);
        int added = preset.targets.size() - before;
        if (added > 0) {
            if (preset.detail.length() > 0) preset.detail += " | ";
            preset.detail += label + " +" + added;
        }
    }

    private void addRelevantSni(LinkedHashSet<String> snis, String needle) {
        for (String sni : loadAsset("scan-corpora/community-sni-hosts.txt")) {
            if (sni.toLowerCase(Locale.US).contains(needle)) snis.add(sni);
        }
    }

    private void startScan() {
        if (executor != null && !executor.isShutdown()) return;
        stop.set(false);
        allResults.clear();
        checkedTargets.set(0);
        scanStartedAt = System.currentTimeMillis();
        resultList.removeAllViews();
        logView.setText("");
        bestView.setText("Best result will appear here");

        List<String> targets = cap(expandTargets(lines(targetsInput.getText().toString())), intValue(totalInput, 72000));
        List<String> snis = lines(snisInput.getText().toString());
        List<Integer> ports = parsePorts(portsInput.getText().toString());
        if (targets.isEmpty() || ports.isEmpty()) {
            toast("Targets and ports are required");
            return;
        }
        if (snis.isEmpty()) snis = Collections.singletonList("");
        List<Integer> workflowProfiles = selectedWorkflowProfiles();
        totalTargets = targets.size() * Math.max(1, workflowProfiles.size());
        int batch = Math.max(1, intValue(batchInput, 12000));
        int threads = Math.max(1, intValue(threadsInput, 64));
        int timeout = Math.max(1, intValue(timeoutInput, 3000));

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        status.setText("Running");
        appendLog("Scan started: targets=" + totalTargets + ", ports=" + ports + ", batch=" + batch +
                ", threads=" + threads + ", workflow=" + workflowSpinner.getSelectedItem() +
                ", steps=" + workflowLabels(workflowProfiles));
        appendResourceWarnings(threads, batch, timeout, targets.size());
        executor = Executors.newFixedThreadPool(threads);
        List<String> finalSnis = snis;
        new Thread(() -> runWorkflow(targets, finalSnis, ports, batch, timeout, workflowProfiles), "scan-orchestrator").start();
    }

    private List<Integer> selectedWorkflowProfiles() {
        ArrayList<Integer> profiles = new ArrayList<>();
        int mode = workflowSpinner == null ? 0 : workflowSpinner.getSelectedItemPosition();
        if (mode == 1) {
            profiles.add(0);
            profiles.add(1);
            profiles.add(2);
            profiles.add(3);
        } else if (mode == 2) {
            if (stepTcp != null && stepTcp.isChecked()) profiles.add(0);
            if (stepTls != null && stepTls.isChecked()) profiles.add(1);
            if (stepHttp != null && stepHttp.isChecked()) profiles.add(2);
            if (stepVerify != null && stepVerify.isChecked()) profiles.add(3);
        } else {
            profiles.add(profileSpinner == null ? 1 : profileSpinner.getSelectedItemPosition());
        }
        if (profiles.isEmpty()) profiles.add(profileSpinner == null ? 1 : profileSpinner.getSelectedItemPosition());
        return profiles;
    }

    private String workflowLabels(List<Integer> profiles) {
        ArrayList<String> labels = new ArrayList<>();
        for (int profile : profiles) labels.add(profileName(profile));
        return joinComma(labels);
    }

    private String profileName(int profile) {
        switch (profile) {
            case 0: return "TCP";
            case 1: return "TLS";
            case 2: return "HTTP";
            case 3: return "Verify";
            default: return "Profile " + profile;
        }
    }

    private void runWorkflow(List<String> targets, List<String> snis, List<Integer> ports, int batchSize,
                             int timeout, List<Integer> profiles) {
        for (int i = 0; i < profiles.size() && !stop.get(); i++) {
            int profile = profiles.get(i);
            boolean allSni = multiSni.isChecked() || profile >= 2;
            appendLog("Workflow step " + (i + 1) + "/" + profiles.size() + ": " + profileName(profile) +
                    (allSni ? " with multi-SNI" : " with primary SNI"));
            runBatches(targets, snis, ports, batchSize, timeout, profile, allSni);
        }
        executor.shutdownNow();
        ui.post(() -> {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            status.setText(stop.get() ? "Stopped" : "Ready");
            appendLog((stop.get() ? "Stopped" : "Complete") + " in " + elapsed());
            updateProgress();
            renderResults();
        });
    }

    private void runBatches(List<String> targets, List<String> snis, List<Integer> ports, int batchSize,
                            int timeout, int profile, boolean allSni) {
        int batches = (targets.size() + batchSize - 1) / batchSize;
        for (int start = 0, batchNo = 1; start < targets.size() && !stop.get(); start += batchSize, batchNo++) {
            List<String> batch = targets.subList(start, Math.min(targets.size(), start + batchSize));
            appendLog(profileName(profile) + " batch " + batchNo + "/" + batches + ": " + batch.size() + " targets");
            CountDownLatch latch = new CountDownLatch(batch.size());
            for (String target : batch) {
                executor.submit(() -> {
                    try { scanTarget(target, snis, ports, timeout, profile, allSni); }
                    finally {
                        checkedTargets.incrementAndGet();
                        updateProgress();
                        latch.countDown();
                    }
                });
            }
            try { latch.await(); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }
    }

    private void appendResourceWarnings(int threads, int batch, int timeout, int targets) {
        if (threads >= 256 || batch >= 72000 || targets >= 72000) {
            appendLog("Warning: high-volume scan selected. Android may throttle sockets, battery, or thermal performance.");
        }
        if (timeout < 250) {
            appendLog("Warning: very low timeout may miss slow-but-working edges.");
        }
    }

    private void scanTarget(String target, List<String> snis, List<Integer> ports, int timeout, int profile, boolean allSni) {
        if (stop.get()) return;
        List<String> ips = resolve(target);
        if (ips.isEmpty()) {
            addResult(Result.down(target, "", 0, "", "dns_failed"));
            return;
        }
        for (String ip : ips) {
            if (stop.get()) return;
            for (int port : ports) {
                Result base = new Result(target, ip, port, "");
                base.tcp(timeout);
                if (profile == 0 || !base.tcpPass) {
                    addResult(base.finish());
                    continue;
                }
                List<String> candidates = allSni ? snis : Collections.singletonList(isIp(target) ? first(snis) : target);
                for (String sni : candidates) {
                    if (stop.get()) return;
                    if (sni == null || sni.trim().isEmpty()) continue;
                    Result r = new Result(target, ip, port, sni.trim());
                    r.tcpPass = base.tcpPass;
                    r.tcpLatencyMs = base.tcpLatencyMs;
                    r.tls(timeout);
                    if (profile >= 2 && r.tlsPass) r.http(timeout, pathInput.getText().toString());
                    addResult(r.finish());
                    if (profile == 3 && r.httpPass) break;
                }
            }
        }
    }

    private void addResult(Result r) {
        allResults.add(r);
        if (!hideNoisyLogs.isChecked() && (r.tlsPass || r.httpPass || allResults.size() % 200 == 0)) {
            appendLog("Result " + r.address() + " sni=" + dash(r.sni) + " tcp=" + r.tcpPass +
                    " tls=" + r.tlsPass + " http=" + r.httpPass + " q=" + Math.round(r.quality));
        }
        scheduleRender();
    }

    private void updateProgress() {
        ui.post(() -> {
            progress.setMax(Math.max(1, totalTargets));
            progress.setProgress(Math.min(checkedTargets.get(), totalTargets));
            Stats s = stats();
            metrics.setText(checkedTargets.get() + " / " + totalTargets + " | TCP " + s.tcp +
                    " | TLS " + s.tls + " | HTTP " + s.http + " | Q " + Math.round(s.bestQuality) + " | " + elapsed());
            countersView.setText("Down " + s.down + " | timeout " + s.timeout + " | reset " + s.reset +
                    " | cert " + s.cert + " | DNS " + s.dns + " | " + resourceLine());
            if (s.best != null) bestView.setText("Best: " + s.best.summary());
        });
    }

    private void scheduleRender() {
        if (!renderQueued.compareAndSet(false, true)) return;
        ui.postDelayed(() -> {
            renderQueued.set(false);
            renderResults();
        }, 350);
    }

    private void renderResults() {
        if (resultList == null) return;
        List<Result> snapshot = filteredResults();
        updateAnalytics(snapshot);
        resultList.removeAllViews();
        if (snapshot.isEmpty()) {
            resultList.addView(emptyVaultView());
            return;
        }
        if (vaultModeSpinner != null && vaultModeSpinner.getSelectedItemPosition() == 1) {
            resultList.addView(heatmapView(snapshot));
            return;
        }
        int limit = Math.min(intValue(resultLimitInput, 250), snapshot.size());
        for (int i = 0; i < limit; i++) resultList.addView(resultView(snapshot.get(i)));
    }

    private View emptyVaultView() {
        LinearLayout card = column();
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.setBackground(glassBg(Color.rgb(10, 28, 41), Color.argb(130, 255, 255, 255)));
        TextView icon = text("⌕", 34, BLUE, true);
        icon.setGravity(Gravity.CENTER);
        card.addView(icon);
        card.addView(text("No visible edges yet", 16, Color.WHITE, true));
        card.addView(text("Pick provider cards, review the valid target chips, then start the Auto multi-step ladder. If a scan already ran, loosen filters to reveal hidden rows.", 12, Color.rgb(205, 226, 238), false));
        Button cta = button("Go to Target Setup", Color.rgb(22, 54, 72), Color.WHITE);
        cta.setOnClickListener(v -> scrollTo(targetAnchor));
        card.addView(cta);
        return card;
    }

    private void updateAnalytics(List<Result> rows) {
        if (analyticsPanel == null) return;
        analyticsPanel.removeAllViews();
        analyticsPanel.addView(text("Live analytics", 15, Color.WHITE, true));
        if (rows == null || rows.isEmpty()) {
            analyticsPanel.addView(text("Visible-result charts appear here while the scan runs. The dashboard respects your active filters, sort, and best-per-IP setting.", 12, MUTED, false));
            return;
        }
        int total = rows.size(), http = 0, tls = 0, tcp = 0, down = 0;
        int fast = 0, medium = 0, slow = 0, verySlow = 0;
        Map<String, Integer> cdns = new TreeMap<>();
        for (Result r : rows) {
            if (r.httpPass) http++;
            else if (r.tlsPass) tls++;
            else if (r.tcpPass) tcp++;
            else down++;
            long latency = r.totalLatency();
            if (latency > 0 && latency < 120) fast++;
            else if (latency > 0 && latency < 300) medium++;
            else if (latency > 0 && latency < 700) slow++;
            else if (latency > 0) verySlow++;
            String cdn = r.cdn == null || r.cdn.trim().isEmpty() ? "UNKNOWN" : r.cdn.toUpperCase(Locale.US);
            cdns.put(cdn, cdns.containsKey(cdn) ? cdns.get(cdn) + 1 : 1);
        }
        analyticsPanel.addView(text("Status distribution", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        analyticsPanel.addView(metricBar("HTTP", http, total, Color.rgb(66, 230, 170)));
        analyticsPanel.addView(metricBar("TLS", tls, total, Color.rgb(55, 212, 255)));
        analyticsPanel.addView(metricBar("TCP", tcp, total, Color.rgb(255, 204, 100)));
        analyticsPanel.addView(metricBar("Down", down, total, Color.rgb(255, 112, 135)));
        analyticsPanel.addView(text("Latency histogram", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        analyticsPanel.addView(metricBar("<120ms", fast, total, Color.rgb(66, 230, 170)));
        analyticsPanel.addView(metricBar("120-299ms", medium, total, Color.rgb(55, 212, 255)));
        analyticsPanel.addView(metricBar("300-699ms", slow, total, Color.rgb(255, 204, 100)));
        analyticsPanel.addView(metricBar("700ms+", verySlow, total, Color.rgb(255, 112, 135)));
        analyticsPanel.addView(text("CDN mix", 12, highContrastMode() ? Color.WHITE : MUTED, true));
        ArrayList<Map.Entry<String, Integer>> groups = new ArrayList<>(cdns.entrySet());
        groups.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        for (int i = 0; i < Math.min(5, groups.size()); i++) {
            Map.Entry<String, Integer> e = groups.get(i);
            analyticsPanel.addView(metricBar(e.getKey(), e.getValue(), total, cdnColor(e.getKey())));
        }
    }

    private View metricBar(String label, int value, int total, int color) {
        LinearLayout box = column();
        box.setPadding(0, dp(3), 0, dp(3));
        String textValue = label + "  " + value + "/" + Math.max(1, total) + "  " + Math.round(value * 100f / Math.max(1, total)) + "%";
        box.addView(text(textValue, compactMode() ? 10 : 11, Color.WHITE, false));
        FrameLayout track = new FrameLayout(this);
        track.setBackground(glassBg(Color.rgb(25, 38, 49), Color.argb(60, 255, 255, 255)));
        TextView fill = text("", 1, Color.TRANSPARENT, false);
        fill.setBackground(glassBg(color, Color.argb(140, 255, 255, 255)));
        FrameLayout.LayoutParams fillLp = new FrameLayout.LayoutParams(Math.max(dp(3), Math.round(dp(220) * value / (float)Math.max(1, total))), dp(7));
        track.addView(fill, fillLp);
        box.addView(track, new LinearLayout.LayoutParams(-1, dp(7)));
        box.setContentDescription(textValue);
        return box;
    }

    private int cdnColor(String cdn) {
        String c = cdn == null ? "" : cdn.toLowerCase(Locale.US);
        if (c.contains("cloudflare")) return Color.rgb(255, 156, 67);
        if (c.contains("fastly")) return Color.rgb(226, 74, 94);
        if (c.contains("akamai")) return Color.rgb(54, 166, 255);
        if (c.contains("aws") || c.contains("cloudfront")) return Color.rgb(255, 204, 100);
        return BLUE;
    }

    private View heatmapView(List<Result> rows) {
        LinearLayout panel = column();
        panel.setPadding(dp(12), dp(10), dp(12), dp(12));
        panel.setBackground(glassBg(Color.rgb(8, 24, 36), Color.argb(120, 255, 255, 255)));
        panel.addView(text("CIDR heatmap overview", 15, Color.WHITE, true));
        panel.addView(text("Each tile is a filtered result: green HTTP, cyan TLS, amber TCP, red failed.", 12, MUTED, false));
        int columns = 16;
        LinearLayout row = null;
        int limit = Math.min(rows.size(), 512);
        for (int i = 0; i < limit; i++) {
            if (i % columns == 0) {
                row = row();
                row.setGravity(Gravity.START);
                panel.addView(row);
            }
            Result r = rows.get(i);
            TextView tile = text("", 1, Color.TRANSPARENT, false);
            tile.setMinHeight(dp(15));
            tile.setMinWidth(dp(15));
            tile.setBackground(glassBg(tileColor(r), Color.argb(70, 255, 255, 255)));
            tile.setContentDescription(r.summary());
            tile.setOnClickListener(v -> copyOne(r));
            row.addView(tile, heatTileLp());
        }
        if (rows.size() > limit) panel.addView(text("Showing first " + limit + " of " + rows.size() + " filtered results.", 11, MUTED, false));
        return panel;
    }

    private LinearLayout.LayoutParams heatTileLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(16), dp(16));
        lp.setMargins(dp(2), dp(2), dp(2), dp(2));
        return lp;
    }

    private int tileColor(Result r) {
        if (r.httpPass) return Color.rgb(20, 160, 105);
        if (r.tlsPass) return Color.rgb(17, 132, 170);
        if (r.tcpPass) return Color.rgb(156, 119, 26);
        return Color.rgb(112, 39, 52);
    }

    private List<Result> filteredResults() {
        List<Result> snapshot;
        synchronized (allResults) { snapshot = new ArrayList<>(allResults); }
        int maxLatency = intValue(maxLatencyInput, 0);
        String cdn = cdnFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String cert = certFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        String sni = sniFilterInput.getText().toString().trim().toLowerCase(Locale.US);
        int minQuality = intValue(minQualityInput, 0);
        snapshot.removeIf(r -> (filterWorking.isChecked() && !r.working()) ||
                (filterSni.isChecked() && !(r.tlsPass || r.httpPass)) ||
                (requireHttp.isChecked() && !r.httpPass) ||
                (requireKnownCdn.isChecked() && "UNKNOWN".equalsIgnoreCase(r.cdn)) ||
                (requireTls13.isChecked() && !r.tlsVersion.contains("1.3")) ||
                (maxLatency > 0 && (r.totalLatency() <= 0 || r.totalLatency() > maxLatency)) ||
                (minQuality > 0 && r.quality < minQuality) ||
                (!cdn.isEmpty() && !r.cdn.toLowerCase(Locale.US).contains(cdn)) ||
                (!sni.isEmpty() && !r.sni.toLowerCase(Locale.US).contains(sni)) ||
                (!cert.isEmpty() && !r.tlsCert.toLowerCase(Locale.US).contains(cert)));
        if (bestPerIp.isChecked()) {
            Map<String, Result> best = new LinkedHashMap<>();
            for (Result r : snapshot) {
                String key = r.ip + ":" + r.port;
                Result old = best.get(key);
                if (old == null || r.quality > old.quality) best.put(key, r);
            }
            snapshot = new ArrayList<>(best.values());
        }
        int sort = sortSpinner.getSelectedItemPosition();
        if (sort == 1) snapshot.sort(Comparator.comparingLong(r -> r.totalLatency() > 0 ? r.totalLatency() : Long.MAX_VALUE));
        else if (sort == 2) snapshot.sort((a, b) -> Double.compare(b.quality, a.quality));
        else if (sort == 3) snapshot.sort(Comparator.comparing((Result r) -> r.cdn).thenComparing((a, b) -> Double.compare(b.quality, a.quality)));
        else if (sort == 4) snapshot.sort(Comparator.comparing((Result r) -> r.sni));
        else if (sort == 5) snapshot.sort((a, b) -> Boolean.compare(b.httpPass, a.httpPass) != 0 ? Boolean.compare(b.httpPass, a.httpPass) : Double.compare(b.quality, a.quality));
        else if (sort == 6) snapshot.sort((a, b) -> Boolean.compare(b.tlsPass, a.tlsPass) != 0 ? Boolean.compare(b.tlsPass, a.tlsPass) : Double.compare(b.quality, a.quality));
        else Collections.reverse(snapshot);
        return snapshot;
    }

    private View resultView(Result r) {
        LinearLayout card = column();
        card.setPadding(dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8), dp(compactMode() ? 8 : 10), dp(compactMode() ? 5 : 8));
        int fill = r.httpPass ? Color.rgb(9, 48, 38) : r.tlsPass ? Color.rgb(16, 45, 37) :
                r.tcpPass ? Color.rgb(43, 36, 16) : Color.rgb(37, 20, 28);
        card.setBackground(glassBg(fill, r.working() ? Color.argb(145, 55, 212, 255) : Color.argb(95, 255, 255, 255)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.setMargins(0, dp(compactMode() ? 4 : 7), 0, 0);
        card.setLayoutParams(lp);
        TextView top = text(r.address() + "  " + dash(r.sni), compactMode() ? 12 : 13, Color.WHITE, true);
        top.setTypeface(Typeface.MONOSPACE);
        LinearLayout signal = row();
        signal.setGravity(Gravity.START);
        signal.addView(statusDot("TCP", r.tcpPass, Color.rgb(54, 166, 255)), smallChipLp());
        signal.addView(statusDot("TLS", r.tlsPass, Color.rgb(66, 230, 170)), smallChipLp());
        signal.addView(statusDot("HTTP", r.httpPass, Color.rgb(255, 204, 100)), smallChipLp());
        signal.addView(statusDot(r.cdn, !"UNKNOWN".equalsIgnoreCase(r.cdn), BLUE), smallChipLp());
        TextView body = text(latencySparkline(r) + "  " + r.totalLatency() + "ms | HTTP " + r.httpStatus +
                " | Q " + Math.round(r.quality), 12, Color.WHITE, false);
        body.setTypeface(Typeface.MONOSPACE);
        card.addView(top);
        card.addView(signal);
        card.addView(body);
        if (!compactMode() && !r.tlsVersion.isEmpty()) card.addView(text(r.tlsVersion + " | " + r.tlsCipher, 11, highContrastMode() ? Color.WHITE : MUTED, false));
        if (!compactMode() && !r.tlsCert.isEmpty()) card.addView(text(trim(r.tlsCert, 120), 11, highContrastMode() ? Color.WHITE : MUTED, false));
        if (!r.reason.isEmpty()) card.addView(text(r.reason, 11, Color.rgb(255, 180, 180), false));
        card.setOnClickListener(v -> copyOne(r));
        card.setContentDescription(r.summary());
        return card;
    }

    private TextView statusDot(String label, boolean on, int color) {
        String prefix = highContrastMode() ? (on ? "[on] " : "[off] ") : (on ? "● " : "○ ");
        TextView v = text(prefix + label, compactMode() ? 10 : 11, on ? Color.WHITE : (highContrastMode() ? Color.rgb(225, 235, 240) : MUTED), false);
        int offFill = highContrastMode() ? Color.rgb(46, 58, 70) : Color.rgb(27, 38, 49);
        int border = on ? Color.argb(210, 255, 255, 255) : Color.argb(highContrastMode() ? 145 : 70, 255, 255, 255);
        v.setBackground(glassBg(on ? color : offFill, border));
        v.setPadding(dp(compactMode() ? 5 : 7), dp(compactMode() ? 3 : 4), dp(compactMode() ? 5 : 7), dp(compactMode() ? 3 : 4));
        v.setContentDescription(label + (on ? " passed" : " not passed"));
        return v;
    }

    private String latencySparkline(Result r) {
        long[] values = {r.tcpLatencyMs, r.tlsLatencyMs, r.httpLatencyMs};
        StringBuilder sb = new StringBuilder();
        for (long value : values) {
            if (value <= 0) sb.append("-");
            else if (value < 120) sb.append("▁");
            else if (value < 300) sb.append("▃");
            else if (value < 700) sb.append("▅");
            else sb.append("█");
        }
        return sb.toString();
    }

    private void copyOne(Result r) {
        clip(r.address() + " " + r.sni + " q=" + Math.round(r.quality));
        toast("Copied result");
    }

    private void copySelectedFormat() {
        List<Result> rows = filteredResults();
        int format = exportSpinner.getSelectedItemPosition();
        StringBuilder sb = new StringBuilder();
        try {
            if (format == 3) {
                sb.append("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,cdn,quality,reason\n");
            } else if (format == 4) {
                JSONArray arr = new JSONArray();
                for (Result r : rows) if (r.working()) arr.put(r.json());
                clip(arr.toString(2));
                toast("Copied JSON");
                return;
            }
            LinkedHashSet<String> dedupe = new LinkedHashSet<>();
            for (Result r : rows) if (r.working()) {
                if (format == 0) dedupe.add(r.ip);
                else if (format == 1) dedupe.add(r.ip);
                else if (format == 2) dedupe.add(r.address() + " " + r.sni);
                else if (format == 3) sb.append(r.csv()).append('\n');
            }
            if (format == 0) sb.append(joinLines(dedupe));
            else if (format == 1) sb.append(joinComma(dedupe));
            else if (format == 2) sb.append(joinLines(dedupe));
            clip(sb.toString());
            toast("Copied " + exportSpinner.getSelectedItem());
        } catch (Exception e) {
            toast("Copy failed: " + e.getMessage());
        }
    }

    private void copyWorking(boolean csv) {
        List<Result> rows = filteredResults();
        StringBuilder sb = new StringBuilder();
        if (csv) sb.append("target,ip,port,sni,tcp,tls,http,http_status,latency_ms,cdn,quality,reason\n");
        for (Result r : rows) if (r.working()) {
            if (csv) sb.append(r.csv()).append('\n');
            else sb.append(r.address()).append(' ').append(r.sni).append(" q=").append(Math.round(r.quality))
                    .append(" cdn=").append(r.cdn).append('\n');
        }
        clip(sb.toString());
        toast(csv ? "Copied CSV" : "Copied working results");
    }

    private void exportJson() {
        try {
            JSONArray arr = new JSONArray();
            for (Result r : filteredResults()) arr.put(r.json());
            File out = new File(getExternalFilesDir(null), "maybe_edge_scan_" + System.currentTimeMillis() + ".json");
            try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
                w.write(arr.toString(2));
            }
            toast("Exported: " + out.getAbsolutePath());
        } catch (Exception e) {
            toast("Export failed: " + e.getMessage());
        }
    }

    private void clearResults() {
        stop.set(true);
        allResults.clear();
        checkedTargets.set(0);
        totalTargets = 0;
        progress.setProgress(0);
        resultList.removeAllViews();
        logView.setText("");
        metrics.setText("0 / 0 | TCP 0 | TLS 0 | HTTP 0 | Q 0");
        countersView.setText("Down 0 | timeout 0 | reset 0 | cert 0 | DNS 0 | " + resourceLine());
        bestView.setText("Best result will appear here");
    }

    private Stats stats() {
        Stats s = new Stats();
        synchronized (allResults) {
            for (Result r : allResults) {
                if (r.tcpPass) s.tcp++;
                if (r.tlsPass) s.tls++;
                if (r.httpPass) s.http++;
                if (!r.working()) s.down++;
                String reason = r.reason.toLowerCase(Locale.US);
                if (reason.contains("timeout")) s.timeout++;
                if (reason.contains("reset")) s.reset++;
                if (reason.contains("cert")) s.cert++;
                if (reason.contains("dns")) s.dns++;
                if (r.quality > s.bestQuality) { s.bestQuality = r.quality; s.best = r; }
            }
        }
        return s;
    }

    private static class Stats {
        int tcp, tls, http, down, timeout, reset, cert, dns;
        double bestQuality;
        Result best;
    }

    private static class Result {
        final String target, ip, sni;
        final int port;
        boolean tcpPass, tlsPass, httpPass;
        long tcpLatencyMs, tlsLatencyMs, httpLatencyMs;
        int httpStatus;
        String tlsVersion = "", tlsCipher = "", tlsCert = "", certFingerprint = "", reason = "", cdn = "UNKNOWN";
        double quality;

        Result(String target, String ip, int port, String sni) {
            this.target = target; this.ip = ip; this.port = port; this.sni = sni == null ? "" : sni;
        }
        static Result down(String target, String ip, int port, String sni, String reason) {
            Result r = new Result(target, ip, port, sni); r.reason = reason; return r.finish();
        }
        void tcp(int timeout) {
            long t = System.currentTimeMillis();
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(ip, port), timeout);
                tcpPass = true; tcpLatencyMs = System.currentTimeMillis() - t;
            } catch (Exception e) { reason = classify(e); }
        }
        void tls(int timeout) {
            long t = System.currentTimeMillis();
            try {
                Socket raw = new Socket();
                raw.connect(new InetSocketAddress(ip, port), timeout);
                raw.setSoTimeout(timeout);
                SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, sni, port, true);
                ssl.setSoTimeout(timeout);
                ssl.startHandshake();
                tlsPass = true; tlsLatencyMs = System.currentTimeMillis() - t;
                tlsVersion = ssl.getSession().getProtocol();
                tlsCipher = ssl.getSession().getCipherSuite();
                Certificate[] certs = ssl.getSession().getPeerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate c = (X509Certificate) certs[0];
                    tlsCert = c.getSubjectX500Principal().getName();
                    certFingerprint = sha256(c.getEncoded());
                }
                ssl.close();
            } catch (Exception e) { reason = classify(e); }
        }
        void http(int timeout, String path) {
            long t = System.currentTimeMillis();
            try {
                Socket raw = new Socket();
                raw.connect(new InetSocketAddress(ip, port), timeout);
                raw.setSoTimeout(timeout);
                SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, sni, port, true);
                ssl.setSoTimeout(timeout);
                ssl.startHandshake();
                String safePath = path == null || path.trim().isEmpty() ? "/" : path.trim();
                if (!safePath.startsWith("/")) safePath = "/" + safePath;
                OutputStream out = ssl.getOutputStream();
                out.write(("HEAD " + safePath + " HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\nUser-Agent: MaybeScanner/1.1\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
                String line = new BufferedReader(new InputStreamReader(ssl.getInputStream(), StandardCharsets.US_ASCII)).readLine();
                httpStatus = parseStatus(line);
                httpPass = httpStatus > 0 && httpStatus < 500;
                httpLatencyMs = System.currentTimeMillis() - t;
                ssl.close();
            } catch (Exception e) { reason = classify(e); }
        }
        Result finish() {
            cdn = detectCdn(ip, sni, tlsCert);
            double stage = (tcpPass ? 25 : 0) + (tlsPass ? 35 : 0) + (httpPass ? 25 : 0);
            long latency = totalLatency();
            double latencyScore = latency > 0 ? 10000.0 / (latency + 100.0) : 0;
            quality = stage + latencyScore * 0.25 + (tlsVersion.contains("1.3") ? 8 : 0) +
                    (!certFingerprint.isEmpty() ? 8 : 0) + (cdn.equals("UNKNOWN") ? 0 : 6) - (reason.isEmpty() ? 0 : 7);
            return this;
        }
        boolean working() { return tcpPass || tlsPass || httpPass; }
        String address() { return ip + ":" + port; }
        long totalLatency() { return (tcpPass ? tcpLatencyMs : 0) + (tlsPass ? tlsLatencyMs : 0) + (httpPass ? httpLatencyMs : 0); }
        String summary() { return address() + " " + sni + " " + cdn + " q=" + Math.round(quality) + " " + totalLatency() + "ms"; }
        JSONObject json() throws Exception {
            JSONObject o = new JSONObject();
            o.put("target", target); o.put("ip", ip); o.put("port", port); o.put("sni", sni);
            o.put("tcpPass", tcpPass); o.put("tlsPass", tlsPass); o.put("httpPass", httpPass);
            o.put("tcpLatencyMs", tcpLatencyMs); o.put("tlsLatencyMs", tlsLatencyMs); o.put("httpLatencyMs", httpLatencyMs);
            o.put("httpStatus", httpStatus); o.put("tlsVersion", tlsVersion); o.put("tlsCipher", tlsCipher);
            o.put("tlsCert", tlsCert); o.put("certFingerprint", certFingerprint); o.put("cdn", cdn);
            o.put("quality", quality); o.put("reason", reason); return o;
        }
        String csv() {
            return q(target)+","+q(ip)+","+port+","+q(sni)+","+tcpPass+","+tlsPass+","+httpPass+","+httpStatus+","+
                    totalLatency()+","+q(cdn)+","+Math.round(quality)+","+q(reason);
        }
    }

    private List<String> loadAsset(String name) {
        List<String> out = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(getAssets().open(name), StandardCharsets.UTF_8))) {
            String line; while ((line = br.readLine()) != null) if (!line.trim().isEmpty() && !line.trim().startsWith("#")) out.add(line.trim());
        } catch (IOException ignored) {}
        return out;
    }
    private LinkedHashSet<String> loadAssetTokens(String name) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String raw : loadAsset(name)) {
            String clean = raw.replace("[", " ").replace("]", " ").replace("\"", " ").replace(",", " ").trim();
            for (String token : clean.split("\\s+")) {
                token = cleanToken(token);
                if (!token.isEmpty() && token.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) out.add(token);
            }
        }
        return out;
    }
    private static List<String> lines(String s) { return unique(Arrays.asList(s.split("[,;\\s\\r\\n]+"))); }
    private static List<String> unique(Collection<String> in) {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        for (String x : in) {
            if (x == null || x.trim().isEmpty()) continue;
            String clean = cleanToken(x);
            if (!clean.isEmpty()) set.add(clean);
        }
        return new ArrayList<>(set);
    }
    private static List<Integer> parsePorts(String s) {
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        for (String p : s.split("[,;\\s]+")) {
            try { int v = Integer.parseInt(p.trim()); if (v > 0 && v < 65536) ports.add(v); } catch (Exception ignored) {}
        }
        if (ports.isEmpty()) ports.add(443);
        return new ArrayList<>(ports);
    }
    private static List<String> cap(List<String> in, int n) { return in.subList(0, Math.min(in.size(), Math.max(1, n))); }
    private static String first(List<String> xs) { return xs.isEmpty() ? "" : xs.get(0); }
    private static boolean isIp(String x) {
        if (x == null) return false;
        String v = x.trim();
        if (v.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            String[] parts = v.split("\\.");
            for (String part : parts) {
                try { int n = Integer.parseInt(part); if (n < 0 || n > 255) return false; }
                catch (Exception e) { return false; }
            }
            return true;
        }
        if (!v.contains(":") || !v.matches("(?i)[0-9a-f:.]+")) return false;
        try { return InetAddress.getByName(v) instanceof Inet6Address; }
        catch (Exception e) { return false; }
    }
    private static List<String> resolve(String target) {
        try {
            if (isIp(target)) return Collections.singletonList(target);
            InetAddress[] a = InetAddress.getAllByName(target);
            List<String> out = new ArrayList<>();
            for (InetAddress x : a) if (x instanceof Inet6Address) out.add(x.getHostAddress());
            for (InetAddress x : a) if (x instanceof Inet4Address) out.add(x.getHostAddress());
            return unique(out);
        } catch (Exception e) { return Collections.emptyList(); }
    }
    private static List<String> expandTargets(List<String> raw) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String x : raw) if (x.contains("/")) out.addAll(expandCidr(x, 200000)); else out.add(x);
        return new ArrayList<>(out);
    }
    private static List<String> expandCidr(String cidr, int cap) {
        List<String> out = new ArrayList<>();
        try {
            String[] p = cidr.split("/");
            if (p.length != 2 || !isIp(p[0])) return out;
            if (p[0].contains(":")) return expandIpv6Cidr(p[0], Integer.parseInt(p[1]), cap);
            long ip = ipv4ToLong(p[0]); int prefix = Integer.parseInt(p[1]);
            if (prefix < 0 || prefix > 32) return out;
            long mask = prefix == 0 ? 0 : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            long start = ip & mask, end = start | (~mask & 0xffffffffL);
            for (long v = start + 1; v < end && out.size() < cap; v++) out.add(longToIpv4(v));
        } catch (Exception ignored) {}
        return out;
    }
    private static List<String> expandIpv6Cidr(String ipText, int prefix, int cap) {
        List<String> out = new ArrayList<>();
        try {
            if (prefix < 0 || prefix > 128 || cap <= 0) return out;
            byte[] bytes = InetAddress.getByName(ipText).getAddress();
            BigInteger ip = new BigInteger(1, bytes);
            BigInteger all = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
            BigInteger mask = prefix == 0 ? BigInteger.ZERO : all.shiftRight(128 - prefix).shiftLeft(128 - prefix);
            BigInteger start = ip.and(mask);
            BigInteger size = BigInteger.ONE.shiftLeft(128 - prefix);
            BigInteger current = start;
            if (size.compareTo(BigInteger.ONE) > 0) current = current.add(BigInteger.ONE);
            for (int i = 0; i < cap && current.subtract(start).compareTo(size) < 0; i++) {
                out.add(bigToIpv6(current));
                current = current.add(BigInteger.ONE);
            }
        } catch (Exception ignored) {}
        return out;
    }
    private static String bigToIpv6(BigInteger value) throws Exception {
        byte[] raw = value.toByteArray();
        byte[] bytes = new byte[16];
        int src = Math.max(0, raw.length - 16);
        int len = Math.min(16, raw.length);
        System.arraycopy(raw, src, bytes, 16 - len, len);
        return InetAddress.getByAddress(bytes).getHostAddress();
    }
    private static long ipv4ToLong(String ip) { String[] p = ip.split("\\."); long r = 0; for (String s : p) r = (r << 8) | Integer.parseInt(s); return r & 0xffffffffL; }
    private static String longToIpv4(long v) { return ((v>>24)&255)+"."+((v>>16)&255)+"."+((v>>8)&255)+"."+(v&255); }
    private static int parseStatus(String line) { try { return line != null && line.startsWith("HTTP/") ? Integer.parseInt(line.split(" ")[1]) : 0; } catch (Exception e) { return 0; } }
    private static String classify(Exception e) {
        String m = String.valueOf(e.getMessage()).toLowerCase(Locale.US);
        if (m.contains("timed")) return "timeout";
        if (m.contains("refused")) return "refused";
        if (m.contains("reset")) return "reset";
        if (m.contains("cert") || m.contains("trust") || m.contains("handshake")) return "cert_or_tls";
        return e.getClass().getSimpleName();
    }
    private static String detectCdn(String ip, String sni, String cert) {
        String hay = (sni + " " + cert).toLowerCase(Locale.US);
        if (hay.contains("cloudflare") || ip.startsWith("104.16.") || ip.startsWith("104.17.") || ip.startsWith("104.18.") || ip.startsWith("172.64.")) return "CLOUDFLARE";
        if (hay.contains("fastly") || ip.startsWith("151.101.")) return "FASTLY";
        if (hay.contains("akamai") || ip.startsWith("23.") || ip.startsWith("2.") || ip.startsWith("92.12") || ip.startsWith("184.") || ip.startsWith("96.")) return "AKAMAI";
        if (hay.contains("amazon") || hay.contains("cloudfront")) return "CLOUDFRONT";
        if (ip.startsWith("95.216.") || ip.startsWith("65.109.")) return "HETZNER";
        return "UNKNOWN";
    }
    private static String sha256(byte[] bytes) throws Exception { byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes); StringBuilder sb = new StringBuilder(); for (byte b : d) sb.append(String.format("%02x", b)); return sb.toString(); }
    private static String joinLines(Collection<String> xs) { StringBuilder sb = new StringBuilder(); for (String x : xs) sb.append(x).append('\n'); return sb.toString().trim(); }
    private static String joinComma(Collection<String> xs) { StringBuilder sb = new StringBuilder(); for (String x : xs) { if (sb.length() > 0) sb.append(','); sb.append(x); } return sb.toString(); }
    private static String q(String s) { return "\"" + String.valueOf(s).replace("\"", "\"\"") + "\""; }
    private static String trim(String s, int n) { return s.length() <= n ? s : s.substring(0, n - 1) + "..."; }
    private static String dash(String s) { return s == null || s.isEmpty() ? "--" : s; }
    private static String cleanToken(String s) { return s.trim().replace("\"", "").replace(",", "").replace("[", "").replace("]", ""); }
    private String yes(boolean b) { return b ? "yes" : "no"; }
    private String elapsed() { long s = Math.max(0, (System.currentTimeMillis() - scanStartedAt) / 1000); return s + "s"; }
    private void clip(String s) { ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("MaybeScanner", s)); }
    private String resourceLine() {
        Intent battery = registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        int level = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = battery == null ? -1 : battery.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        int pct = level >= 0 && scale > 0 ? Math.round(level * 100f / scale) : -1;
        Runtime rt = Runtime.getRuntime();
        long usedMb = (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
        return "battery " + (pct >= 0 ? pct + "%" : "n/a") + " | heap " + usedMb + "MB";
    }
    private void appendLog(String s) { ui.post(() -> logView.append(new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "  " + s + "\n")); }
    private int intValue(EditText e, int fallback) { try { String s = e.getText().toString().trim(); return s.isEmpty() ? fallback : Integer.parseInt(s); } catch (Exception ex) { return fallback; } }
    private LinearLayout column() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }
    private LinearLayout row() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER); return l; }
    private TextView text(String s, int sp, int color, boolean bold) { TextView v = new TextView(this); v.setText(s); v.setTextSize(sp); v.setTextColor(color); if (bold) v.setTypeface(Typeface.DEFAULT_BOLD); v.setPadding(0, dp(4), 0, dp(4)); return v; }
    private TextView panelText(String s) { TextView v = text(s, 12, Color.WHITE, false); v.setBackground(glassBg(PANEL, Color.argb(120, 255, 255, 255))); v.setPadding(dp(12), dp(10), dp(12), dp(10)); setOuterMargin(v, 0, dp(6), 0, dp(6)); return v; }
    private TextView glassText(String s) { TextView v = panelText(s); v.setTextColor(Color.rgb(196, 223, 235)); return v; }
    private TextView infoCard(String title, String body) { TextView v = panelText(title + "\n" + body); v.setTextColor(Color.rgb(220, 238, 248)); return v; }
    private TextView section(String s) { TextView v = text(s, 12, Color.rgb(180, 215, 230), true); v.setPadding(dp(2), dp(12), 0, dp(4)); v.setLetterSpacing(0.08f); return v; }
    private TextView pill(String s) { TextView v = text(s, 13, BLUE, true); v.setGravity(Gravity.CENTER); v.setBackground(glassBg(Color.rgb(16, 35, 50), BLUE)); v.setPadding(dp(12), dp(8), dp(12), dp(8)); setOuterMargin(v, 0, dp(8), 0, dp(8)); return v; }
    private EditText area(String hint) { EditText e = input("", false); e.setHint(hint); e.setMinLines(4); e.setGravity(Gravity.TOP); return e; }
    private EditText input(String s, boolean number) { EditText e = new EditText(this); e.setText(s); e.setTextColor(Color.WHITE); e.setTextSize(14); e.setHintTextColor(Color.rgb(145, 174, 190)); e.setSingleLine(false); e.setInputType((number ? InputType.TYPE_CLASS_NUMBER : InputType.TYPE_CLASS_TEXT) | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS); e.setBackground(glassBg(FIELD, Color.argb(95, 255, 255, 255))); e.setPadding(dp(12), dp(10), dp(12), dp(10)); return e; }
    private CheckBox check(String s) { CheckBox c = new CheckBox(this); c.setText(s); c.setTextSize(13); c.setTextColor(Color.WHITE); c.setButtonTintList(android.content.res.ColorStateList.valueOf(BLUE)); return c; }
    private Button button(String s, int bg, int fg) { Button b = new Button(this); b.setText(s); b.setTextColor(fg); b.setTextSize(13); b.setAllCaps(false); b.setTypeface(Typeface.DEFAULT_BOLD); b.setBackground(glassBg(bg, Color.argb(135, 255, 255, 255))); b.setPadding(dp(10), dp(8), dp(10), dp(8)); b.setOnTouchListener((v, e) -> { if (e.getAction() == android.view.MotionEvent.ACTION_DOWN) { v.performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP); v.animate().scaleX(0.98f).scaleY(0.98f).setDuration(70).start(); } if (e.getAction() == android.view.MotionEvent.ACTION_UP || e.getAction() == android.view.MotionEvent.ACTION_CANCEL) v.animate().scaleX(1f).scaleY(1f).setDuration(130).setInterpolator(new DecelerateInterpolator()).start(); return false; }); return b; }
    private Spinner spinner(String[] values) { Spinner s = new Spinner(this); ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, values); s.setAdapter(adapter); s.setBackground(glassBg(FIELD, Color.argb(95, 255, 255, 255))); s.setPadding(dp(8), dp(6), dp(8), dp(6)); return s; }
    private LinearLayout box(String label, View child) { LinearLayout l = column(); l.setBackground(glassBg(Color.rgb(11, 26, 37), Color.argb(75, 255, 255, 255))); l.setPadding(dp(8), dp(4), dp(8), dp(8)); l.addView(section(label)); l.addView(child); return l; }
    private LinearLayout.LayoutParams weight() { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1); lp.setMargins(dp(4), dp(4), dp(4), dp(4)); return lp; }
    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }
    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_LONG).show(); }
    private boolean highContrastMode() { return visualModeSpinner != null && visualModeSpinner.getSelectedItemPosition() == 1; }
    private boolean compactMode() { return visualModeSpinner != null && visualModeSpinner.getSelectedItemPosition() == 2; }
    private GradientDrawable glassBg(int fill, int stroke) {
        int fillAlpha = highContrastMode() ? 245 : 215;
        int shineAlpha = highContrastMode() ? 40 : 120;
        GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{Color.argb(fillAlpha, Color.red(fill), Color.green(fill), Color.blue(fill)), Color.argb(shineAlpha, 255, 255, 255)});
        g.setCornerRadius(dp(compactMode() ? 10 : 16));
        g.setStroke(dp(highContrastMode() ? 2 : 1), stroke);
        return g;
    }
    private void setOuterMargin(View v, int l, int t, int r, int b) { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.setMargins(l, t, r, b); v.setLayoutParams(lp); }

    private static class Preset {
        final String name;
        final LinkedHashSet<String> targets = new LinkedHashSet<>();
        final LinkedHashSet<String> snis = new LinkedHashSet<>();
        String detail = "";
        Preset(String name) { this.name = name; }
    }
}
