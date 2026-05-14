package security.whisper.javastix.taxii.auth;

import java.util.Objects;

/**
 * RFC 6750 Bearer token authentication. The token value is sent verbatim
 * with a {@code Bearer } prefix.
 */
public final class BearerAuth implements TaxiiCredentials {

    private final String header;

    public BearerAuth(String token) {
        Objects.requireNonNull(token, "token");
        this.header = "Bearer " + token;
    }

    @Override
    public String authorizationHeader() {
        return header;
    }
}
