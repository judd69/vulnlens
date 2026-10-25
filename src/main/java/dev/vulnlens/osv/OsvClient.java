package dev.vulnlens.osv;

import dev.vulnlens.model.Dependency;
import dev.vulnlens.model.VulnRecord;
import dev.vulnlens.parse.Json;

import java.io.IOException;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Queries the live OSV.dev API ({@code POST /v1/querybatch}) in polite
 * batches. Honors the standard {@code https_proxy}/{@code http_proxy} (and
 * uppercase) environment variables, including embedded credentials, plus
 * {@code no_proxy}. All network/parse failures surface as
 * {@link VulnerabilitySource.OsvException} with a human-readable message.
 */
public final class OsvClient implements VulnerabilitySource {

    public static final String API_URL = "https://api.osv.dev/v1/querybatch";
    public static final String USER_AGENT = "vulnlens/1.0 (+https://github.com/judd69/vulnlens)";
    private static final int BATCH_SIZE = 50;

    private final HttpClient http;
    private final Duration requestTimeout;
    private long lastQueryMillis;

    public OsvClient(Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
        HttpClient.Builder b = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL);
        ProxySelector proxy = proxyFromEnv();
        if (proxy != null) b.proxy(proxy);
        this.http = b.build();
    }

    @Override
    public long lastQueryMillis() { return lastQueryMillis; }

    @Override
    public List<List<VulnRecord>> query(List<Dependency> deps) throws OsvException {
        long t0 = System.nanoTime();
        try {
            List<List<VulnRecord>> all = new ArrayList<>();
            for (int i = 0; i < deps.size(); i += BATCH_SIZE) {
                List<Dependency> batch = deps.subList(i, Math.min(i + BATCH_SIZE, deps.size()));
                all.addAll(queryBatch(batch));
                // gentle pacing between batches
                if (i + BATCH_SIZE < deps.size()) {
                    try { Thread.sleep(400); } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new OsvException("interrupted while querying OSV.dev");
                    }
                }
            }
            return all;
        } finally {
            lastQueryMillis = (System.nanoTime() - t0) / 1_000_000;
        }
    }

    private List<List<VulnRecord>> queryBatch(List<Dependency> batch) throws OsvException {
        String body = buildRequest(batch);
        HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL))
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new OsvException("cannot reach OSV.dev (" + API_URL + "): " + shortMsg(e), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OsvException("interrupted while querying OSV.dev");
        }
        if (resp.statusCode() != 200) {
            throw new OsvException("OSV.dev returned HTTP " + resp.statusCode()
                    + " — the API may be having issues, try again in a bit");
        }
        try {
            return OsvMapper.parseBatch(resp.body(), batch);
        } catch (Json.ParseException | IllegalArgumentException e) {
            throw new OsvException("OSV.dev returned an unexpected response: " + e.getMessage());
        }
    }

    /** Build the querybatch request body. Package-private for tests/tooling. */
    static String buildRequest(List<Dependency> batch) {
        StringBuilder sb = new StringBuilder("{\"queries\":[");
        for (int i = 0; i < batch.size(); i++) {
            Dependency d = batch.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"package\":{\"name\":").append(quote(d.coordinate()))
              .append(",\"ecosystem\":\"Maven\"},\"version\":").append(quote(d.version())).append('}');
        }
        return sb.append("]}").toString();
    }

    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }

    private static String shortMsg(IOException e) {
        String m = e.getMessage();
        // Sandbox/proxy policy pages sometimes leak into the exception text —
        // never surface those verbatim; the class name plus a hint is enough.
        if (m == null || m.isBlank() || m.contains("muse:") || m.length() > 300) {
            return e.getClass().getSimpleName() + " (check your network connection and proxy settings)";
        }
        return m.length() > 160 ? m.substring(0, 157) + "..." : m;
    }

    // ------------------------------------------------------------------
    // Proxy support from the environment (https_proxy / http_proxy, no_proxy)
    // ------------------------------------------------------------------

    private static ProxySelector proxyFromEnv() {
        String raw = firstNonBlank(System.getenv("https_proxy"), System.getenv("HTTPS_PROXY"),
                System.getenv("http_proxy"), System.getenv("HTTP_PROXY"));
        if (raw == null) return null;
        try {
            URI uri = URI.create(raw.trim());
            String host = uri.getHost();
            int port = uri.getPort() < 0 ? 8080 : uri.getPort();
            if (host == null) return null;
            String userInfo = uri.getUserInfo();
            if (userInfo != null && !userInfo.isEmpty()) {
                int c = userInfo.indexOf(':');
                String user = c < 0 ? userInfo : userInfo.substring(0, c);
                String pass = c < 0 ? "" : userInfo.substring(c + 1);
                Authenticator.setDefault(new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(user, pass.toCharArray());
                    }
                });
            }
            List<String> noProxy = parseNoProxy();
            InetSocketAddress addr = new InetSocketAddress(host, port);
            return new ProxySelector() {
                @Override
                public List<java.net.Proxy> select(URI u) {
                    if (matchesNoProxy(u.getHost(), noProxy)) return List.of(java.net.Proxy.NO_PROXY);
                    return List.of(new java.net.Proxy(java.net.Proxy.Type.HTTP, addr));
                }
                @Override
                public void connectFailed(URI u, java.net.SocketAddress sa, IOException ioe) {}
            };
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static List<String> parseNoProxy() {
        String raw = firstNonBlank(System.getenv("no_proxy"), System.getenv("NO_PROXY"));
        List<String> out = new ArrayList<>();
        if (raw != null) {
            for (String p : raw.split(",")) {
                p = p.trim().toLowerCase(Locale.ROOT);
                if (!p.isEmpty()) out.add(p.startsWith(".") ? p.substring(1) : p);
            }
        }
        return out;
    }

    private static boolean matchesNoProxy(String host, List<String> noProxy) {
        if (host == null || noProxy.isEmpty()) return false;
        String h = host.toLowerCase(Locale.ROOT);
        for (String p : noProxy) {
            if (h.equals(p) || h.endsWith("." + p)) return true;
        }
        return false;
    }

    private static String firstNonBlank(String... vals) {
        for (String v : vals) if (v != null && !v.isBlank()) return v;
        return null;
    }
}
