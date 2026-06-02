package com.maybescanner;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

public class ScanForegroundService extends Service {
    public static final String ACTION_START = "com.maybescanner.service.START";
    public static final String ACTION_UPDATE = "com.maybescanner.service.UPDATE";
    public static final String ACTION_STOP = "com.maybescanner.service.STOP";
    public static final String ACTION_CANCEL_SCAN = "com.maybescanner.service.CANCEL_SCAN";
    public static final String ACTION_COMMAND = "com.maybescanner.service.COMMAND";
    public static final String ACTION_STATE_CHANGED = "com.maybescanner.service.STATE_CHANGED";
    public static final String EXTRA_STATE = "state";
    public static final String EXTRA_DETAIL = "detail";
    public static final String EXTRA_PROGRESS = "progress";

    private static final String CHANNEL_ID = "scan_lifecycle";
    private static final int NOTIFICATION_ID = 1201;
    private static final AtomicReference<ScanLifecycleSnapshot> SNAPSHOT =
            new AtomicReference<>(new ScanLifecycleSnapshot("idle", "No active scan", 0));
    private static final AtomicReference<ScanSessionSnapshot> SESSION =
            new AtomicReference<>(ScanSessionSnapshot.empty());

    private PowerManager.WakeLock wakeLock;

    public static ScanLifecycleSnapshot snapshot() {
        return SNAPSHOT.get();
    }

    public static ScanSessionSnapshot sessionSnapshot() {
        return SESSION.get();
    }

    public static void beginSession(long generation, int plannedChecks, int targets, int ports, int workers, String workflow) {
        SESSION.set(new ScanSessionSnapshot(
                "scan-" + generation,
                generation,
                Math.max(0, plannedChecks),
                0,
                Math.max(0, targets),
                Math.max(0, ports),
                Math.max(0, workers),
                workflow == null ? "" : workflow,
                "running",
                System.currentTimeMillis(),
                0L
        ));
    }

    public static void updateSessionProgress(int completedChecks) {
        ScanSessionSnapshot current = SESSION.get();
        SESSION.set(current.withProgress(completedChecks, "running", 0L));
    }

    public static void finishSession(String state) {
        ScanSessionSnapshot current = SESSION.get();
        SESSION.set(current.withProgress(current.completedChecks, state == null ? "idle" : state, System.currentTimeMillis()));
    }

    static void restoreProcessLostSession(ScanProcessContinuityStore.AbandonedSession abandoned) {
        if (abandoned == null) return;
        SESSION.set(new ScanSessionSnapshot(
                abandoned.generation <= 0 ? "" : "scan-" + abandoned.generation,
                abandoned.generation,
                abandoned.plannedChecks,
                0,
                0,
                0,
                0,
                abandoned.workflow,
                "process_lost",
                abandoned.startedAtEpochMs,
                System.currentTimeMillis()
        ));
        SNAPSHOT.set(new ScanLifecycleSnapshot("process_lost", abandoned.detail(), 0));
    }

    public static void enterPlanReview(Context context, String detail) {
        ScanSessionController.get().setPlanReviewPending(true);
        update(context, "waiting_for_confirmation", detail, 0);
    }

    static boolean isWaitingForPlanConfirmation() {
        return "waiting_for_confirmation".equals(snapshot().state)
                || ScanSessionController.get().isPlanReviewPending();
    }

    public static void start(Context context, String state, String detail, int progress) {
        Intent intent = new Intent(context, ScanForegroundService.class)
                .setAction(ACTION_START)
                .putExtra(EXTRA_STATE, state)
                .putExtra(EXTRA_DETAIL, detail)
                .putExtra(EXTRA_PROGRESS, progress);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    public static void update(Context context, String state, String detail, int progress) {
        Intent intent = new Intent(context, ScanForegroundService.class)
                .setAction(ACTION_UPDATE)
                .putExtra(EXTRA_STATE, state)
                .putExtra(EXTRA_DETAIL, detail)
                .putExtra(EXTRA_PROGRESS, progress);
        String normalizedState = state == null ? "" : state.trim().toLowerCase(Locale.US);
        boolean active = "running".equals(normalizedState)
                || "planning".equals(normalizedState)
                || "cancelling".equals(normalizedState)
                || "waiting_for_confirmation".equals(normalizedState);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && active) {
                context.startForegroundService(intent);
            } else {
                context.startService(intent);
            }
        } catch (IllegalStateException blocked) {
            publishFallbackLifecycle(context, state, detail, progress);
        }
    }

    public static void stop(Context context, String detail) {
        Intent intent = new Intent(context, ScanForegroundService.class)
                .setAction(ACTION_STOP)
                .putExtra(EXTRA_STATE, "idle")
                .putExtra(EXTRA_DETAIL, detail)
                .putExtra(EXTRA_PROGRESS, 0);
        context.startService(intent);
    }

    @Override public void onCreate() {
        super.onCreate();
        ScanSessionController.get().attachApplicationContext(getApplicationContext());
        ScanWorkflowEngine.ensureRegistered();
        SidecarTokenStore.getOrCreate(getApplicationContext());
        SidecarLauncher.ensureRunning(getApplicationContext());
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_UPDATE : intent.getAction();
        if (ACTION_COMMAND.equals(action)) {
            ScanCommand command = readCommand(intent);
            if (command != null) {
                handleCommand(command);
            }
            return START_STICKY;
        }
        if (ACTION_CANCEL_SCAN.equals(action)) {
            handleCommand(ScanCommand.cancelScan("notification_legacy", sessionSnapshot().generation));
            return START_STICKY;
        }
        if (ACTION_STOP.equals(action)) {
            applySnapshot("idle", extra(intent, EXTRA_DETAIL, "Scan inactive"), 0);
            finishSession("idle");
            ScanProcessContinuityStore.markTerminal(getApplicationContext());
            releaseWakeLock();
            stopForeground(true);
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        String state = extra(intent, EXTRA_STATE, "running");
        String detail = extra(intent, EXTRA_DETAIL, "Scan running");
        int progress = intent == null ? snapshot().progress : intent.getIntExtra(EXTRA_PROGRESS, snapshot().progress);
        applySnapshot(state, detail, progress);
        createChannel();
        if ("running".equals(state) || "cancelling".equals(state) || "planning".equals(state)
                || "waiting_for_confirmation".equals(state)) {
            acquireWakeLock();
        } else {
            releaseWakeLock();
        }
        startForeground(NOTIFICATION_ID, buildNotification(snapshot()));
        return START_STICKY;
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }

    @Override public void onDestroy() {
        if (ScanSessionController.get().isRunning()) {
            ScanSessionController.get().noteProcessContinuityLost();
        }
        SidecarHeartbeatGuard.get().stop();
        releaseWakeLock();
        super.onDestroy();
    }

    private void applySnapshot(String state, String detail, int progress) {
        int boundedProgress = Math.max(0, Math.min(100, progress));
        ScanLifecycleSnapshot next = new ScanLifecycleSnapshot(state, detail, boundedProgress);
        SNAPSHOT.set(next);
        sendBroadcast(new Intent(ACTION_STATE_CHANGED)
                .setPackage(getPackageName())
                .putExtra(EXTRA_STATE, next.state)
                .putExtra(EXTRA_DETAIL, next.detail)
                .putExtra(EXTRA_PROGRESS, next.progress));
    }

    private void handleCommand(ScanCommand command) {
        switch (command.kind) {
            case START_SCAN:
                if (ScanSessionController.get().isPlanReviewPending()
                        && (command.stagingRequest == null || !command.stagingRequest.planConfirmed)) {
                    applySnapshot("waiting_for_confirmation", "Review scan plan before starting", 0);
                    ScanSessionController.get().notifyUiObservers();
                    break;
                }
                ScanSessionController.get().setPlanReviewPending(false);
                applySnapshot("planning", "Scan start requested", 0);
                if (command.stagingRequest != null) {
                    ScanSessionStager.Result staged = ScanSessionStager.apply(this, command.stagingRequest);
                    if (!staged.success) {
                        terminalizeStartFailure(staged.error, ScanTerminalReason.FAILED_START);
                        break;
                    }
                }
                SidecarLauncher.LaunchResult sidecar = SidecarLauncher.ensureRunning(this);
                if (ScanSessionController.get().commitStagedLaunch()) {
                    ScanSessionSnapshot session = sessionSnapshot();
                    int plannedChecks = Math.max(0, session.plannedChecks);
                    if (plannedChecks == 0) {
                        terminalizeStartFailure("No checks planned. Select targets before starting.",
                                ScanTerminalReason.FAILED_NO_CHECKS);
                        break;
                    }
                    applySnapshot("running", "0 / " + plannedChecks + " checks", 0);
                    SidecarHeartbeatGuard.get().onScanStarted(this, sidecar.reachable);
                } else if (command.stagingRequest == null) {
                    terminalizeStartFailure("No staged scan inputs", ScanTerminalReason.FAILED_START);
                }
                ScanSessionController.get().notifyUiObservers();
                break;
            case CLEAR_SESSION:
                ScanSessionController.get().performClearSession();
                applySnapshot("idle", "Scan cleared", 0);
                finishSession("idle");
                ScanProcessContinuityStore.markTerminal(getApplicationContext());
                releaseWakeLock();
                stopForeground(true);
                ScanSessionController.get().notifyUiObservers();
                break;
            case CANCEL_SCAN:
                SidecarHeartbeatGuard.get().stop();
                if (ScanSessionController.get().matchesCommandGeneration(command.generation)) {
                    ScanSessionController.get().requestStop();
                    ScanSessionController.get().recordTerminalReason(
                            ScanTerminalReason.fromStopRequested(true, command.source));
                }
                applySnapshot("cancelling", "Stop requested from " + command.source, snapshot().progress);
                ScanSessionController.get().notifyUiObservers();
                break;
            case STOP_SIDECAR:
                SidecarController.get().requestShutdownAsync();
                applySnapshot(snapshot().state, "Sidecar stop requested", snapshot().progress);
                break;
            case EXPORT_RESULTS:
                if (command.exportSpec != null) {
                    ScanSessionController.get().stageExport(command.exportSpec);
                }
                ScanResultExporter.Result exportResult = ScanSessionController.get().runStagedExport(getApplicationContext());
                if (exportResult.success()) {
                    applySnapshot(snapshot().state, "Exported " + exportResult.path, snapshot().progress);
                } else if (isStorageExportError(exportResult.error)) {
                    ScanSessionController.get().noteStorageFailure();
                    applySnapshot("failed", "Export storage failed: " + exportResult.error, snapshot().progress);
                } else {
                    ScanSessionController.get().recordTerminalReason(ScanTerminalReason.FAILED_EXPORT);
                    applySnapshot("failed", "Export failed: " + exportResult.error, snapshot().progress);
                }
                sendBroadcast(ScanExportBus.completedBroadcast(exportResult.path, exportResult.error).setPackage(getPackageName()));
                break;
            case REFRESH_PROVIDER_READINESS:
                org.json.JSONObject corpus = SidecarController.get().fetchProviderCorpusJson(1200);
                if (corpus != null && corpus.optBoolean("stale", false)
                        && ScanSessionController.get().isRunning()) {
                    ScanSessionController.get().noteProviderFailure();
                    applySnapshot("failed", "Provider corpus stale during scan", snapshot().progress);
                } else {
                    String detail = corpus == null
                            ? "Provider readiness refresh requested"
                            : "Provider corpus id=" + corpus.optString("corpus_id", "unknown");
                    applySnapshot(snapshot().state, detail, snapshot().progress);
                }
                ScanSessionController.get().notifyUiObservers();
                break;
            default:
                break;
        }
        createChannel();
        if ("running".equals(snapshot().state) || "cancelling".equals(snapshot().state) || "planning".equals(snapshot().state)
                || "waiting_for_confirmation".equals(snapshot().state)) {
            acquireWakeLock();
        }
        startForeground(NOTIFICATION_ID, buildNotification(snapshot()));
        sendBroadcast(ScanCommandBus.commandBroadcast(command).setPackage(getPackageName()));
    }

    private static boolean isStorageExportError(String error) {
        if (error == null || error.trim().isEmpty()) return false;
        String lower = error.toLowerCase(Locale.US);
        return lower.contains("permission")
                || lower.contains("enospc")
                || lower.contains("no space")
                || lower.contains("read-only")
                || lower.contains("read only")
                || lower.contains("eacces")
                || lower.contains("storage")
                || lower.contains("ioexception");
    }

    private void terminalizeStartFailure(String detail, ScanTerminalReason reason) {
        ScanTerminalReason terminal = reason == null ? ScanTerminalReason.FAILED_START : reason;
        SidecarHeartbeatGuard.get().stop();
        ScanSessionController.get().requestStop();
        ScanSessionController.get().recordTerminalReason(terminal);
        ScanSessionController.get().shutdownExecutor();
        applySnapshot(terminal.lifecycleState, detail == null || detail.trim().isEmpty()
                ? "Scan start failed" : detail, 0);
        finishSession(terminal.lifecycleState);
        ScanProcessContinuityStore.markTerminal(getApplicationContext());
        releaseWakeLock();
        ScanSessionController.get().notifyUiObservers();
    }

    private static ScanCommand readCommand(Intent intent) {
        if (intent == null) return null;
        Object value = intent.getSerializableExtra(ScanCommandBus.EXTRA_COMMAND);
        return value instanceof ScanCommand ? (ScanCommand) value : null;
    }

    private Notification buildNotification(ScanLifecycleSnapshot state) {
        Intent openIntent = new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent open = PendingIntent.getActivity(this, 0, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Intent cancelIntent = new Intent(this, ScanForegroundService.class)
                .setAction(ACTION_COMMAND)
                .putExtra(ScanCommandBus.EXTRA_COMMAND,
                        ScanCommand.cancelScan("notification", sessionSnapshot().generation));
        PendingIntent cancel = PendingIntent.getService(this, 1, cancelIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        builder.setSmallIcon(R.drawable.maybescanner_logo)
                .setContentTitle("MaybeScanner scan")
                .setContentText(state.detail)
                .setSubText(state.state)
                .setContentIntent(open)
                .setOngoing(!"idle".equals(state.state) && !"completed".equals(state.state) && !"failed".equals(state.state))
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .addAction(R.drawable.maybescanner_logo, "Stop", cancel);
        if (state.progress > 0 && state.progress < 100) {
            builder.setProgress(100, state.progress, false);
        }
        return builder.build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (manager == null || manager.getNotificationChannel(CHANNEL_ID) != null) return;
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Active scans", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Shows active scan lifecycle state and stop control.");
        manager.createNotificationChannel(channel);
    }

    private void acquireWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) return;
        PowerManager powerManager = (PowerManager) getSystemService(POWER_SERVICE);
        if (powerManager == null) return;
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MaybeScanner:scan");
        wakeLock.setReferenceCounted(false);
        wakeLock.acquire(30 * 60 * 1000L);
    }

    private void releaseWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        wakeLock = null;
    }

    private static String extra(Intent intent, String key, String fallback) {
        if (intent == null) return fallback;
        String value = intent.getStringExtra(key);
        return value == null || value.trim().isEmpty() ? fallback : value;
    }

    static void publishFallbackLifecycle(Context context, String state, String detail, int progress) {
        int boundedProgress = Math.max(0, Math.min(100, progress));
        ScanLifecycleSnapshot next = new ScanLifecycleSnapshot(
                state == null || state.trim().isEmpty() ? "running" : state.trim(),
                detail == null || detail.trim().isEmpty() ? "Scan running" : detail.trim(),
                boundedProgress
        );
        SNAPSHOT.set(next);
        context.sendBroadcast(new Intent(ACTION_STATE_CHANGED)
                .setPackage(context.getPackageName())
                .putExtra(EXTRA_STATE, next.state)
                .putExtra(EXTRA_DETAIL, next.detail)
                .putExtra(EXTRA_PROGRESS, next.progress));
    }

    public static final class ScanLifecycleSnapshot {
        public final String state;
        public final String detail;
        public final int progress;

        ScanLifecycleSnapshot(String state, String detail, int progress) {
            this.state = state;
            this.detail = detail;
            this.progress = progress;
        }
    }

    public static final class ScanSessionSnapshot {
        public final String sessionId;
        public final long generation;
        public final int plannedChecks;
        public final int completedChecks;
        public final int targets;
        public final int ports;
        public final int workers;
        public final String workflow;
        public final String state;
        public final long startedAtEpochMs;
        public final long finishedAtEpochMs;

        ScanSessionSnapshot(String sessionId, long generation, int plannedChecks, int completedChecks,
                            int targets, int ports, int workers, String workflow, String state,
                            long startedAtEpochMs, long finishedAtEpochMs) {
            this.sessionId = sessionId;
            this.generation = generation;
            this.plannedChecks = plannedChecks;
            this.completedChecks = completedChecks;
            this.targets = targets;
            this.ports = ports;
            this.workers = workers;
            this.workflow = workflow;
            this.state = state;
            this.startedAtEpochMs = startedAtEpochMs;
            this.finishedAtEpochMs = finishedAtEpochMs;
        }

        static ScanSessionSnapshot empty() {
            return new ScanSessionSnapshot("", 0L, 0, 0, 0, 0, 0, "", "idle", 0L, 0L);
        }

        ScanSessionSnapshot withProgress(int completedChecks, String state, long finishedAtEpochMs) {
            int bounded = Math.max(0, Math.min(Math.max(0, plannedChecks), completedChecks));
            return new ScanSessionSnapshot(sessionId, generation, plannedChecks, bounded, targets, ports,
                    workers, workflow, state, startedAtEpochMs, finishedAtEpochMs);
        }
    }
}
