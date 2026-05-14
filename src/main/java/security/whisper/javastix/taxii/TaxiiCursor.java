package security.whisper.javastix.taxii;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import security.whisper.javastix.json.StixParsers;
import security.whisper.javastix.taxii.exception.TaxiiProtocolException;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Opaque, serializable cursor that pins a TAXII pagination position. The
 * cursor stores the {@code added_after} timestamp the next request should
 * carry and, optionally, the {@code next} envelope value from a previous
 * page response.
 *
 * <p>Consumers persist a cursor between runs by calling {@link #toToken()},
 * storing the resulting string, and rebuilding the cursor with
 * {@link #fromToken(String)}.
 */
public final class TaxiiCursor implements Serializable {

    private static final long serialVersionUID = 1L;

    private final Instant addedAfter;
    private final String next;

    @JsonCreator
    TaxiiCursor(@JsonProperty("addedAfter") Instant addedAfter,
                @JsonProperty("next") String next) {
        this.addedAfter = addedAfter;
        this.next = next;
    }

    /**
     * Cursor representing "from the beginning" - emits no {@code added_after}
     * parameter on the first request.
     */
    public static TaxiiCursor begin() {
        return new TaxiiCursor(null, null);
    }

    /**
     * Builds a cursor from a token previously produced by {@link #toToken()}.
     *
     * @throws IllegalArgumentException if the token is not a valid cursor
     *         token (bad base64, malformed JSON, missing fields).
     */
    public static TaxiiCursor fromToken(String token) {
        Objects.requireNonNull(token, "token");
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(token);
            ObjectMapper mapper = StixParsers.getJsonMapper();
            return mapper.readValue(decoded, TaxiiCursor.class);
        } catch (IllegalArgumentException iae) {
            throw new IllegalArgumentException("Cursor token is not valid base64", iae);
        } catch (java.io.IOException ioe) {
            throw new IllegalArgumentException("Cursor token JSON is malformed", ioe);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("addedAfter")
    public Instant addedAfterRaw() { return addedAfter; }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("next")
    public String nextRaw() { return next; }

    public Optional<Instant> getAddedAfter() { return Optional.ofNullable(addedAfter); }
    public Optional<String> getNext() { return Optional.ofNullable(next); }

    /**
     * Serializes the cursor to an opaque URL-safe base64 token. The token
     * is stable as part of the public contract - consumers may persist it
     * and reload it across library versions.
     */
    public String toToken() {
        try {
            byte[] json = StixParsers.getJsonMapper().writeValueAsBytes(this);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        } catch (JsonProcessingException e) {
            throw new TaxiiProtocolException("Failed to serialize TAXII cursor", e);
        }
    }

    /**
     * Returns a new cursor with the {@code added_after} timestamp set,
     * preserving the {@code next} value.
     */
    public TaxiiCursor withAddedAfter(Instant addedAfter) {
        return new TaxiiCursor(addedAfter, this.next);
    }

    /**
     * Returns a new cursor with the {@code next} envelope value set,
     * preserving the {@code added_after} timestamp.
     */
    public TaxiiCursor withNext(String next) {
        return new TaxiiCursor(this.addedAfter, next);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TaxiiCursor)) return false;
        TaxiiCursor that = (TaxiiCursor) o;
        return Objects.equals(addedAfter, that.addedAfter)
                && Objects.equals(next, that.next);
    }

    @Override
    public int hashCode() {
        return Objects.hash(addedAfter, next);
    }

    @Override
    public String toString() {
        return "TaxiiCursor{addedAfter=" + addedAfter + ", next=" + next + "}";
    }

    private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
        out.defaultWriteObject();
    }

    private void readObject(java.io.ObjectInputStream in)
            throws java.io.IOException, ClassNotFoundException {
        in.defaultReadObject();
    }
}
