package com.maybescanner;

import android.app.AlertDialog;
import java.util.function.Consumer;

final class DiagnosticsCopyActions {
    private DiagnosticsCopyActions() {}

    static void copyRedacted(String output, Consumer<String> copier, Consumer<String> toaster) {
        if (output == null || output.trim().isEmpty()) {
            toaster.accept("No diagnostics output to copy");
            return;
        }
        copier.accept(DiagnosticsRedactor.redact(output));
        toaster.accept("MaybeScanner redacted diagnostics copied");
    }

    static void copyFullWithConfirmation(AlertDialog.Builder builder, String output, Consumer<String> copier, Consumer<String> toaster) {
        if (output == null || output.trim().isEmpty()) {
            toaster.accept("No diagnostics output to copy");
            return;
        }
        builder.setTitle("Copy full MaybeScanner diagnostics")
                .setMessage("This may include network context and runtime details. Continue?")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Copy full", (d, w) -> copier.accept(output))
                .show();
    }
}

