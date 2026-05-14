package security.whisper.javastix.taxii.http;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable HTTP response surfaced from a {@link TaxiiHttpClient}. Headers
 * are stored case-insensitively so consumers can look up
 * {@code X-TAXII-Date-Added-Last} regardless of casing returned by the
 * server.
 */
public final class TaxiiHttpResponse {

    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final String body;

    private TaxiiHttpResponse(Builder b) {
        this.statusCode = b.statusCode;
        Map<String, List<String>> normalized = new LinkedHashMap<>();
        b.headers.forEach((k, v) -> normalized.put(
                k.toLowerCase(java.util.Locale.ROOT),
                Collections.unmodifiableList(v)));
        this.headers = Collections.unmodifiableMap(normalized);
        this.body = b.body;
    }

    public int statusCode() { return statusCode; }
    public Map<String, List<String>> headers() { return headers; }
    public String body() { return body; }

    public Optional<String> firstHeader(String name) {
        List<String> values = headers.get(name.toLowerCase(java.util.Locale.ROOT));
        if (values == null || values.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(values.get(0));
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private int statusCode;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private String body = "";

        public Builder statusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder headers(Map<String, List<String>> headers) {
            this.headers.clear();
            headers.forEach((k, v) -> this.headers.put(k, java.util.List.copyOf(v)));
            return this;
        }

        public Builder body(String body) {
            this.body = Objects.requireNonNullElse(body, "");
            return this;
        }

        public TaxiiHttpResponse build() {
            return new TaxiiHttpResponse(this);
        }
    }
}
