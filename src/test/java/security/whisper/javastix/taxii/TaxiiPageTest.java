package security.whisper.javastix.taxii;

import org.junit.jupiter.api.Test;
import security.whisper.javastix.bundle.BundleObject;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

class TaxiiPageTest {

    private static final String BUNDLE_JSON = "{"
            + "\"type\":\"bundle\","
            + "\"id\":\"bundle--00000000-0000-0000-0000-000000000001\","
            + "\"spec_version\":\"2.1\","
            + "\"objects\":[{"
            + "\"type\":\"indicator\","
            + "\"id\":\"indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f\","
            + "\"created\":\"2016-04-06T20:03:48.000Z\","
            + "\"modified\":\"2016-04-06T20:03:48.000Z\","
            + "\"labels\":[\"malicious-activity\"],"
            + "\"pattern\":\"[domain-name:value = 'example.com']\","
            + "\"valid_from\":\"2016-04-06T20:03:48Z\""
            + "}]"
            + "}";

    @Test
    void bundle_isCached() throws Exception {
        TaxiiPage page = new TaxiiPage(BUNDLE_JSON, false, TaxiiCursor.begin(),
                Instant.parse("2024-01-01T00:00:00Z"),
                Instant.parse("2024-01-02T00:00:00Z"));

        BundleObject first = page.bundle();
        BundleObject second = page.bundle();

        assertSame(first, second);
    }

    @Test
    void exposesRawBundleJson() {
        TaxiiPage page = new TaxiiPage(BUNDLE_JSON, false, TaxiiCursor.begin(), null, null);
        assertEquals(BUNDLE_JSON, page.bundleJson());
        assertFalse(page.hasMore());
    }
}
