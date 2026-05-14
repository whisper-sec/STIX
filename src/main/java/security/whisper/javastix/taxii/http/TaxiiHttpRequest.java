package security.whisper.javastix.taxii.http;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable description of an outgoing TAXII HTTP request. The TAXII client
 * builds these and hands them to a {@link TaxiiHttpClient} implementation;
 * v1.4.0 only emits {@code GET} requests but the type carries a method so
 * later push-mode work can add {@code POST} without an SPI break.
 */
public final class TaxiiHttpRequest {

    private final String method;
    private final URI uri;
    private final Map<String, String> headers;

    private TaxiiHttpRequest(Builder b) {
        this.method = b.method;
        this.uri = b.uri;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(b.headers));
    }

    public String method() { return method; }
    public URI uri() { return uri; }
    public Map<String, String> headers() { return headers; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String method = "GET";
        private URI uri;
        private final Map<String, String> headers = new LinkedHashMap<>();

        public Builder method(String method) {
            this.method = Objects.requireNonNull(method, "method");
            return this;
        }

        public Builder uri(URI uri) {
            this.uri = Objects.requireNonNull(uri, "uri");
            return this;
        }

        public Builder header(String name, String value) {
            this.headers.put(
                    Objects.requireNonNull(name, "name"),
                    Objects.requireNonNull(value, "value"));
            return this;
        }

        public TaxiiHttpRequest build() {
            if (uri == null) {
                throw new IllegalStateException("uri is required");
            }
            return new TaxiiHttpRequest(this);
        }
    }
}
