package com.maybescanner;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ResultExportFormatterTest {
    @Test
    public void lineExportDedupesIpsAndSkipsMissingAddresses() throws Exception {
        String content = ResultExportFormatter.buildNonJsonContent(
                Arrays.asList(result("one.example", "1.1.1.1", 443, ""), result("dupe.example", "1.1.1.1", 443, ""), result("missing", "", 443, "")),
                0,
                false,
                r -> "",
                Row.ACCESSOR);

        assertEquals("1.1.1.1", content);
    }

    @Test
    public void commaExportPreservesFirstSeenOrder() throws Exception {
        String content = ResultExportFormatter.buildNonJsonContent(
                Arrays.asList(result("one.example", "1.1.1.1", 443, ""), result("two.example", "2.2.2.2", 443, "")),
                1,
                false,
                r -> "",
                Row.ACCESSOR);

        assertEquals("1.1.1.1,2.2.2.2", content);
    }

    @Test
    public void pairExportUsesHostHintResolverWhenSniPairingIsDisabled() throws Exception {
        String content = ResultExportFormatter.buildNonJsonContent(
                Collections.singletonList(result("edge.example", "1.1.1.1", 8443, "")),
                2,
                false,
                r -> "edge.example",
                Row.ACCESSOR);

        assertEquals("1.1.1.1:8443 edge.example", content);
    }

    @Test
    public void csvFormatKeepsStructuredResultFields() throws Exception {
        Row row = result("edge.example", "1.1.1.1", 443, "edge.example");

        String csv = ResultExportFormatter.buildNonJsonContent(
                Collections.singletonList(row),
                3,
                false,
                r -> "edge.example",
                Row.ACCESSOR);

        assertTrue(csv.startsWith("target,ip,port,sni,tcp,tls,http"));
        assertTrue(csv.contains("edge.example,1.1.1.1,443"));
    }

    private static Row result(String target, String ip, int port, String sni) {
        return new Row(target, ip, port, sni);
    }

    private static final class Row {
        static final ResultExportFormatter.Accessor<Row> ACCESSOR = new ResultExportFormatter.Accessor<Row>() {
            @Override public String ip(Row row) { return row.ip; }
            @Override public String address(Row row) { return row.ip + ":" + row.port; }
            @Override public String sni(Row row) { return row.sni; }
            @Override public String csv(Row row) {
                return row.target + "," + row.ip + "," + row.port + "," + row.sni + ",true,true,true,200,60,http/1.1,TLS 1.3,,Cloudflare,95,ok";
            }
        };

        final String target;
        final String ip;
        final int port;
        final String sni;

        Row(String target, String ip, int port, String sni) {
            this.target = target;
            this.ip = ip;
            this.port = port;
            this.sni = sni;
        }
    }
}
