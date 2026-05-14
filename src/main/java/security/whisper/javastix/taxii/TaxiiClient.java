package security.whisper.javastix.taxii;

import security.whisper.javastix.taxii.auth.BasicAuth;
import security.whisper.javastix.taxii.auth.TaxiiCredentials;
import security.whisper.javastix.taxii.http.JdkHttpClientAdapter;
import security.whisper.javastix.taxii.http.TaxiiHttpClient;
import security.whisper.javastix.taxii.internal.TaxiiClientImpl;
import security.whisper.javastix.taxii.model.ApiRoot;
import security.whisper.javastix.taxii.model.Collection;
import security.whisper.javastix.taxii.model.Discovery;
import security.whisper.javastix.taxii.model.Manifest;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Pull-mode client for TAXII 2.1 servers. Exposes the discovery, API root,
 * collection, object, and manifest endpoints in a thin, allocation-light
 * way; response bodies are handed off to
 * {@link security.whisper.javastix.json.StixParsers} for STIX parsing
 * rather than re-implemented.
 *
 * <p>The default HTTP transport is the JDK 11 {@code java.net.http.HttpClient}
 * (see {@link JdkHttpClientAdapter}) - no extra dependencies are pulled in.
 * Consumers can plug a different transport (Spring {@code RestClient},
 * OkHttp, etc.) via {@link Builder#httpClient(TaxiiHttpClient)}.
 *
 * <p>The client itself contains no retry, rate-limit, or circuit-breaker
 * logic - those are application-level concerns. Wrap it with Resilience4j
 * or similar if needed.
 *
 * <p>Instances are safe to share across threads. Closing the client only
 * releases resources held by the HTTP adapter (the default JDK adapter is
 * a no-op).
 */
public interface TaxiiClient extends AutoCloseable {

    /** {@code GET /taxii2/} - returns server discovery metadata. */
    Discovery discover();

    /** {@code GET /{api-root}/} - returns metadata about a single API root. */
    ApiRoot apiRoot(String apiRootPath);

    /** {@code GET /{api-root}/collections/} - enumerates collections. */
    List<Collection> collections(ApiRoot apiRoot);

    /** {@code GET /{api-root}/collections/{id}/} - returns a single collection. */
    Collection collection(ApiRoot apiRoot, String collectionId);

    /**
     * {@code GET /{api-root}/collections/{id}/objects/} - fetches one page of
     * STIX objects, applying the cursor and filter as query parameters.
     */
    TaxiiPage objects(ApiRoot apiRoot, Collection collection,
                      TaxiiCursor cursor, TaxiiFilter filter);

    /**
     * Fetches one page of STIX objects from an absolute URL - used to follow
     * a {@code next} link returned by a previous page when the server prefers
     * to drive pagination by URL rather than by cursor token.
     */
    TaxiiPage objects(URI absoluteUrl);

    /**
     * {@code GET /{api-root}/collections/{id}/manifest/} - fetches one page
     * of manifest records. The {@code more}/{@code next} pagination model is
     * the same as for objects.
     */
    Manifest manifest(ApiRoot apiRoot, Collection collection,
                      TaxiiCursor cursor, TaxiiFilter filter);

    /**
     * Releases resources held by the HTTP transport. Optional for the default
     * JDK adapter; bring-your-own adapters may need it.
     */
    @Override
    void close();

    static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link TaxiiClient} instances. */
    final class Builder {
        private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

        private String baseUrl;
        private TaxiiCredentials credentials = TaxiiCredentials.ANONYMOUS;
        private TaxiiHttpClient httpClient;
        private Duration timeout = DEFAULT_TIMEOUT;

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl");
            return this;
        }

        public Builder credentials(TaxiiCredentials credentials) {
            this.credentials = Objects.requireNonNull(credentials, "credentials");
            return this;
        }

        /** Convenience for HTTP Basic. Equivalent to passing a {@link BasicAuth}. */
        public Builder credentials(String username, String password) {
            this.credentials = new BasicAuth(username, password);
            return this;
        }

        public Builder httpClient(TaxiiHttpClient httpClient) {
            this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout, "timeout");
            return this;
        }

        public TaxiiClient build() {
            if (baseUrl == null) {
                throw new IllegalStateException("baseUrl is required");
            }
            TaxiiHttpClient http = httpClient != null
                    ? httpClient
                    : new JdkHttpClientAdapter(timeout);
            return new TaxiiClientImpl(baseUrl, credentials, http);
        }
    }
}
