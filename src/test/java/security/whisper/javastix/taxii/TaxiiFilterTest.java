package security.whisper.javastix.taxii;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaxiiFilterTest {

    @Test
    void empty_isEmptyAndHasNoFields() {
        TaxiiFilter f = TaxiiFilter.none();
        assertTrue(f.isEmpty());
        assertTrue(f.getTypes().isEmpty());
        assertTrue(f.getIds().isEmpty());
        assertFalse(f.getLimit().isPresent());
    }

    @Test
    void builder_accumulatesMultipleTypes() {
        TaxiiFilter f = TaxiiFilter.builder()
                .addType("indicator")
                .addType("malware")
                .build();
        assertEquals(2, f.getTypes().size());
        assertEquals("indicator", f.getTypes().get(0));
        assertEquals("malware", f.getTypes().get(1));
        assertFalse(f.isEmpty());
    }

    @Test
    void limit_mustBePositive() {
        assertThrows(IllegalArgumentException.class,
                () -> TaxiiFilter.builder().limit(0));
        assertThrows(IllegalArgumentException.class,
                () -> TaxiiFilter.builder().limit(-5));
    }

    @Test
    void typesAndIds_areUnmodifiable() {
        TaxiiFilter f = TaxiiFilter.builder()
                .addType("indicator")
                .addId("indicator--abc")
                .build();
        assertThrows(UnsupportedOperationException.class,
                () -> f.getTypes().add("malware"));
        assertThrows(UnsupportedOperationException.class,
                () -> f.getIds().clear());
    }
}
