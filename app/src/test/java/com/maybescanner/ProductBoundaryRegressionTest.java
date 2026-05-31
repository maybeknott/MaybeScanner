package com.maybescanner;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ProductBoundaryRegressionTest {
    @Test
    public void maybeScannerDocsDoNotReintroduceCdnFirstCopy() throws Exception {
        String docs = read("README.md") + "\n"
                + read("docs/USER_GUIDE.md") + "\n"
                + read("docs/ARCHITECTURAL_GUIDE.md") + "\n"
                + read("go-sidecar/README.md");
        String normalized = docs.toLowerCase(Locale.US);

        assertFalse(normalized.contains("pre-flight presets"));
        assertFalse(normalized.contains("global cdns"));
        assertFalse(normalized.contains("verify cdn edge"));
        assertFalse(normalized.contains("edge scan request"));
        assertFalse(normalized.contains("streaming edge scans"));
        assertFalse(normalized.contains("known cdns"));
        assertFalse(normalized.contains("managed sampling horizontal scrubbers"));
        assertFalse(normalized.contains("complete preset"));
        assertFalse(normalized.contains("lock-free bitwise lookups"));
        assertFalse(normalized.contains("initcdnindex"));
    }

    @Test
    public void maybeScannerDocsPreserveIpFirstContract() throws Exception {
        String docs = read("README.md") + "\n"
                + read("docs/USER_GUIDE.md") + "\n"
                + read("go-sidecar/README.md");
        String normalized = docs.toLowerCase(Locale.US);

        assertTrue(normalized.contains("target-first"));
        assertTrue(normalized.contains("literal ip scans do not receive a default sni"));
        assertTrue(normalized.contains("empty scan requests are rejected"));
        assertTrue(normalized.contains("managed corpora"));
        assertTrue(normalized.contains("advanced diagnostics"));
    }

    @Test
    public void defaultClassificationSpinnerUsesGenericNetworkChoices() throws Exception {
        String mainActivity = read("app/src/main/java/com/maybescanner/MainActivity.java");

        assertTrue(mainActivity.contains(
                "new String[]{\"Any network\", \"Known network\", \"Unknown\"}"));
        assertFalse(mainActivity.contains(
                "new String[]{\"Any network\", \"Known network\", \"Akamai\""));
    }

    private static String read(String relativePath) throws IOException {
        return new String(Files.readAllBytes(projectRoot().resolve(relativePath)), StandardCharsets.UTF_8);
    }

    private static Path projectRoot() {
        Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();
        while (dir != null && !Files.exists(dir.resolve("settings.gradle"))) {
            dir = dir.getParent();
        }
        if (dir == null) {
            throw new IllegalStateException("Could not locate MaybeScanner project root");
        }
        return dir;
    }
}
