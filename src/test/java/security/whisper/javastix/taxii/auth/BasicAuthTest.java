package security.whisper.javastix.taxii.auth;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BasicAuthTest {

    @Test
    void encodesUserAndPasswordAsBase64() {
        BasicAuth auth = new BasicAuth("guest", "guest");
        String expected = "Basic " + Base64.getEncoder().encodeToString(
                "guest:guest".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, auth.authorizationHeader());
    }

    @Test
    void colonInUsername_isIncludedVerbatim_thoughNotIdeal() {
        BasicAuth auth = new BasicAuth("api:key", "secret");
        String decoded = new String(Base64.getDecoder().decode(
                auth.authorizationHeader().substring("Basic ".length())),
                StandardCharsets.UTF_8);
        assertEquals("api:key:secret", decoded);
    }

    @Test
    void nullUsername_throws() {
        assertThrows(NullPointerException.class, () -> new BasicAuth(null, "x"));
    }

    @Test
    void nullPassword_throws() {
        assertThrows(NullPointerException.class, () -> new BasicAuth("x", null));
    }

    @Test
    void bearerAuth_attachesBearerPrefix() {
        BearerAuth auth = new BearerAuth("xyz.abc.123");
        assertEquals("Bearer xyz.abc.123", auth.authorizationHeader());
    }

    @Test
    void anonymous_returnsNullHeader() {
        assertNull(TaxiiCredentials.ANONYMOUS.authorizationHeader());
    }
}
