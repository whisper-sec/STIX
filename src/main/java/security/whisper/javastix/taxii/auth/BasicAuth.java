package security.whisper.javastix.taxii.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/**
 * HTTP Basic authentication. The username and password are joined with a
 * colon and base64-encoded once at construction time.
 */
public final class BasicAuth implements TaxiiCredentials {

    private final String header;

    public BasicAuth(String username, String password) {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        String token = Base64.getEncoder().encodeToString(
                (username + ":" + password).getBytes(StandardCharsets.UTF_8));
        this.header = "Basic " + token;
    }

    @Override
    public String authorizationHeader() {
        return header;
    }
}
