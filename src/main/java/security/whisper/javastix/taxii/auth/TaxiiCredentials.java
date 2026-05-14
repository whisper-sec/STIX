package security.whisper.javastix.taxii.auth;

/**
 * SPI for attaching an authentication header to outgoing TAXII requests.
 * Implementations are expected to be stateless and thread-safe.
 *
 * <p>Two ready-made implementations ship with the client: {@link BasicAuth}
 * for HTTP Basic and {@link BearerAuth} for token-based servers. Custom
 * schemes (API keys, signed headers, mTLS-side identifiers) can be plugged
 * in by implementing this interface directly.
 */
@FunctionalInterface
public interface TaxiiCredentials {

    /**
     * Returns the value to place in the {@code Authorization} header, or
     * {@code null} to send the request anonymously. The value should be the
     * complete header value including any scheme prefix (e.g.
     * {@code "Basic dXNlcjpwYXNz"}).
     */
    String authorizationHeader();

    /** Convenience anonymous singleton - emits no Authorization header. */
    TaxiiCredentials ANONYMOUS = () -> null;
}
