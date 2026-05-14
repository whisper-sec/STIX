package security.whisper.javastix.taxii.http;

import java.io.IOException;

/**
 * Service-provider interface for the HTTP transport used by the TAXII
 * client. The default implementation ({@link JdkHttpClientAdapter}) wraps
 * the JDK 11 {@code java.net.http.HttpClient} and is suitable for the
 * common case; consumers can plug in Spring {@code RestClient}, OkHttp, or
 * any other library by implementing this interface and passing it to the
 * client builder.
 *
 * <p>Implementations MUST be thread-safe - a single instance is shared by
 * the {@code TaxiiClient}.
 */
public interface TaxiiHttpClient {

    /**
     * Send the request synchronously and return the response. Implementations
     * should NOT translate HTTP status codes into exceptions - the client
     * orchestration layer handles that. They should, however, raise
     * {@link IOException} for transport-level failures.
     */
    TaxiiHttpResponse send(TaxiiHttpRequest request) throws IOException;
}
