import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal HTTP load tester, no dependencies. Run it with the JDK directly:
 *
 * <pre>
 *   java tools/LoadTest.java http://localhost:8080/api/search?q=laptop
 *   java tools/LoadTest.java -n 20000 -c 16 -w 3000 -X POST -H "Content-Type: application/json" \
 *        -d "{\"text\":\"hello\"}" http://localhost:8080/api/comment
 * </pre>
 *
 * Options: -n requests (default 10000), -c concurrent threads (16), -w warm-up requests that are not
 * measured (2000), -X method, -d body, -H "Name: value" (repeatable).
 * Prints latency percentiles, throughput and the status code distribution.
 * <p>
 * To measure what SecureGate costs, run the same test against the app with and without it
 * (for example {@code --securegate.enabled=false} vs the default) and compare.
 */
public class LoadTest {

    public static void main(String[] args) throws Exception {
        int requests = 10_000, threads = 16, warmup = 2_000;
        String method = "GET", body = null, url = null;
        Map<String, String> headers = new TreeMap<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-n" -> requests = Integer.parseInt(args[++i]);
                case "-c" -> threads = Integer.parseInt(args[++i]);
                case "-w" -> warmup = Integer.parseInt(args[++i]);
                case "-X" -> method = args[++i];
                case "-d" -> body = args[++i];
                case "-H" -> {
                    String h = args[++i];
                    int c = h.indexOf(':');
                    headers.put(h.substring(0, c).trim(), h.substring(c + 1).trim());
                }
                default -> url = args[i];
            }
        }
        if (url == null) {
            System.err.println("usage: java tools/LoadTest.java [-n N] [-c THREADS] [-w WARMUP] [-X METHOD] [-d BODY] [-H \"K: V\"] URL");
            System.exit(2);
        }

        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5)).build();
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30));
        headers.forEach(builder::header);
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        HttpRequest request = builder.build();

        run(client, request, warmup, threads, false);                       // warm-up: JIT, connections
        long start = System.nanoTime();
        Result r = run(client, request, requests, threads, true);
        double seconds = (System.nanoTime() - start) / 1e9;

        long[] sorted = Arrays.copyOf(r.latencies, r.count);
        Arrays.sort(sorted);
        System.out.printf(Locale.ROOT, "%s %s%n", method, url);
        System.out.printf(Locale.ROOT, "requests=%d threads=%d duration=%.2fs throughput=%.0f req/s%n",
                r.count, threads, seconds, r.count / seconds);
        System.out.printf(Locale.ROOT, "latency ms: mean=%.2f p50=%.2f p95=%.2f p99=%.2f max=%.2f%n",
                Arrays.stream(sorted).average().orElse(0) / 1e6, pct(sorted, 50), pct(sorted, 95), pct(sorted, 99),
                sorted[sorted.length - 1] / 1e6);
        System.out.println("status: " + new TreeMap<>(r.statuses) + (r.errors.get() > 0 ? "  errors=" + r.errors : ""));
    }

    private static double pct(long[] sorted, double p) {
        int idx = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(idx, sorted.length - 1))] / 1e6;
    }

    private record Result(long[] latencies, int count, Map<Integer, AtomicInteger> statuses, AtomicInteger errors) {
    }

    private static Result run(HttpClient client, HttpRequest request, int total, int threads, boolean record)
            throws InterruptedException {
        long[] latencies = new long[total];
        AtomicInteger next = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();
        Map<Integer, AtomicInteger> statuses = new ConcurrentHashMap<>();
        CountDownLatch done = new CountDownLatch(threads);
        List<Thread> pool = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            Thread thread = new Thread(() -> {
                try {
                    int i;
                    while ((i = next.getAndIncrement()) < total) {
                        long t0 = System.nanoTime();
                        try {
                            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
                            latencies[i] = System.nanoTime() - t0;
                            statuses.computeIfAbsent(response.statusCode(), k -> new AtomicInteger()).incrementAndGet();
                        } catch (Exception e) {
                            latencies[i] = System.nanoTime() - t0;
                            errors.incrementAndGet();
                        }
                    }
                } finally {
                    done.countDown();
                }
            });
            pool.add(thread);
            thread.start();
        }
        done.await();
        return new Result(latencies, total, statuses, errors);
    }
}
