package security.whisper.javastix.taxii;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaxiiCursorTest {

    @Test
    void begin_hasNoAddedAfterOrNext() {
        TaxiiCursor c = TaxiiCursor.begin();
        assertFalse(c.getAddedAfter().isPresent());
        assertFalse(c.getNext().isPresent());
    }

    @Test
    void token_roundTrip_preservesAllFields() {
        TaxiiCursor original = TaxiiCursor.begin()
                .withAddedAfter(Instant.parse("2024-01-15T10:30:00Z"))
                .withNext("opaque-server-cursor-abc123");

        TaxiiCursor restored = TaxiiCursor.fromToken(original.toToken());
        assertEquals(original, restored);
        assertEquals(Instant.parse("2024-01-15T10:30:00Z"),
                restored.getAddedAfter().orElseThrow());
        assertEquals("opaque-server-cursor-abc123", restored.getNext().orElseThrow());
    }

    @Test
    void token_roundTrip_withOnlyAddedAfter() {
        TaxiiCursor original = TaxiiCursor.begin()
                .withAddedAfter(Instant.parse("2024-06-01T00:00:00Z"));
        TaxiiCursor restored = TaxiiCursor.fromToken(original.toToken());
        assertEquals(original, restored);
        assertFalse(restored.getNext().isPresent());
    }

    @Test
    void fromToken_garbage_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> TaxiiCursor.fromToken("not!base64!!!"));
    }

    @Test
    void fromToken_validBase64_butBadJson_throws() {
        String token = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("not json".getBytes());
        assertThrows(IllegalArgumentException.class,
                () -> TaxiiCursor.fromToken(token));
    }

    @Test
    void serializable_javaIoRoundTrip() throws Exception {
        TaxiiCursor original = TaxiiCursor.begin()
                .withAddedAfter(Instant.parse("2024-01-01T00:00:00Z"));

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(buf)) {
            oos.writeObject(original);
        }
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(buf.toByteArray()))) {
            TaxiiCursor restored = (TaxiiCursor) ois.readObject();
            assertEquals(original, restored);
        }
    }

    @Test
    void withX_doesNotMutateOriginal() {
        TaxiiCursor c1 = TaxiiCursor.begin();
        TaxiiCursor c2 = c1.withAddedAfter(Instant.parse("2024-01-01T00:00:00Z"));
        assertFalse(c1.getAddedAfter().isPresent());
        assertTrue(c2.getAddedAfter().isPresent());
    }
}
