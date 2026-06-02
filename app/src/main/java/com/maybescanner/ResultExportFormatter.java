package com.maybescanner;

import org.json.JSONArray;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

final class ResultExportFormatter {
    private static final String CSV_HEADER = "target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,network_classification,quality,reason\n";

    private ResultExportFormatter() {}

    interface Accessor<T> {
        String ip(T row);
        String address(T row);
        String sni(T row);
        String csv(T row);
    }

    private static final Accessor<MainActivity.Result> RESULT_ACCESSOR = new Accessor<MainActivity.Result>() {
        @Override public String ip(MainActivity.Result row) { return row.ip; }
        @Override public String address(MainActivity.Result row) { return row.address(); }
        @Override public String sni(MainActivity.Result row) { return row.sni; }
        @Override public String csv(MainActivity.Result row) { return row.csv(); }
    };

    static MainActivity.ExportPayload buildSelectedFormat(
            List<MainActivity.Result> rows,
            int format,
            String selectedLabel,
            boolean sniPairingEnabled,
            Function<MainActivity.Result, String> primaryHostHintResolver
    ) throws Exception {
        if (format == 4) {
            JSONArray arr = new JSONArray();
            for (MainActivity.Result r : rows) arr.put(r.json());
            return new MainActivity.ExportPayload("JSON", arr.toString(2));
        }

        return new MainActivity.ExportPayload(String.valueOf(selectedLabel),
                buildNonJsonContent(rows, format, sniPairingEnabled, primaryHostHintResolver, RESULT_ACCESSOR));
    }

    static <T> String buildNonJsonContent(
            List<T> rows,
            int format,
            boolean sniPairingEnabled,
            Function<T, String> primaryHostHintResolver,
            Accessor<T> accessor
    ) {
        StringBuilder sb = new StringBuilder();
        if (format == 3) {
            sb.append(CSV_HEADER);
        }
        LinkedHashSet<String> dedupe = new LinkedHashSet<>();
        for (T r : rows) {
            String ip = accessor.ip(r);
            if (ip == null || ip.isEmpty()) continue;
            if (format == 0 || format == 1) {
                dedupe.add(ip);
                continue;
            }
            if (format == 2) {
                String hint = sniPairingEnabled ? safe(accessor.sni(r)) : safe(primaryHostHintResolver.apply(r));
                dedupe.add((accessor.address(r) + (hint.isEmpty() ? "" : " " + hint)).trim());
                continue;
            }
            if (format == 3) {
                sb.append(accessor.csv(r)).append('\n');
            }
        }

        if (format == 0 || format == 2) {
            sb.append(joinLines(dedupe));
        } else if (format == 1) {
            sb.append(joinComma(dedupe));
        }
        return sb.toString();
    }

    static String buildVisibleCsv(List<MainActivity.Result> rows) {
        StringBuilder sb = new StringBuilder(CSV_HEADER);
        for (MainActivity.Result r : rows) sb.append(r.csv()).append('\n');
        return sb.toString();
    }

    private static String joinLines(LinkedHashSet<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String v : values) {
            if (sb.length() > 0) sb.append('\n');
            sb.append(v);
        }
        return sb.toString();
    }

    private static String joinComma(LinkedHashSet<String> values) {
        StringBuilder sb = new StringBuilder();
        for (String v : values) {
            if (sb.length() > 0) sb.append(',');
            sb.append(v);
        }
        return sb.toString();
    }

    private static String safe(String input) {
        return input == null ? "" : input.trim();
    }
}
