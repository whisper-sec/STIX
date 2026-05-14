package security.whisper.javastix.taxii.http;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Default {@link TaxiiHttpClient} implementation backed by the JDK 11
 * {@code java.net.http.HttpClient}. Adds zero new transitive dependencies
 * to the STIX library.
 */
public final class JdkHttpClientAdapter implements TaxiiHttpClient {

    private final HttpClient delegate;
    private final Duration requestTimeout;

    public JdkHttpClientAdapter(Duration requestTimeout) {
        this(HttpClient.newBuilder()
                .connectTimeout(requestTimeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build(), requestTimeout);
    }

    public JdkHttpClientAdapter(HttpClient delegate, Duration requestTimeout) {
        this.delegate = delegate;
        this.requestTimeout = requestTimeout;
    }

    @Override
    public TaxiiHttpResponse send(TaxiiHttpRequest request) throws IOException {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(request.uri())
                .timeout(requestTimeout)
                .method(request.method(), HttpRequest.BodyPublishers.noBody());
        request.headers().forEach(builder::header);

        try {
            HttpResponse<String> resp = delegate.send(
                    builder.build(), HttpResponse.BodyHandlers.ofString());
            return TaxiiHttpResponse.builder()
                    .statusCode(resp.statusCode())
                    .headers(resp.headers().map())
                    .body(resp.body())
                    .build();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("TAXII HTTP request interrupted", ie);
        }
    }
}
