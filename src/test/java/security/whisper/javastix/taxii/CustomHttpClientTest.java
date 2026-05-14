package security.whisper.javastix.taxii;

import org.junit.jupiter.api.Test;
import security.whisper.javastix.taxii.http.TaxiiHttpClient;
import security.whisper.javastix.taxii.http.TaxiiHttpRequest;
import security.whisper.javastix.taxii.http.TaxiiHttpResponse;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Confirms a consumer-supplied {@link TaxiiHttpClient} is the transport
 * the client uses, so the SPI is genuinely honored.
 */
class CustomHttpClientTest {

    @Test
    void customAdapter_isCalledWithExpectedRequest() {
        AtomicReference<TaxiiHttpRequest> captured = new AtomicReference<>();
        TaxiiHttpClient capturing = new TaxiiHttpClient() {
            @Override
            public TaxiiHttpResponse send(TaxiiHttpRequest request) throws IOException {
                captured.set(request);
                return TaxiiHttpResponse.builder()
                        .statusCode(200)
                        .headers(java.util.Map.of(
                                "Content-Type", List.of("application/taxii+json;version=2.1")))
                        .body("{\"title\":\"hi\",\"api_roots\":[]}")
                        .build();
            }
        };

        TaxiiClient client = TaxiiClient.builder()
                .baseUrl("https://example.invalid/")
                .httpClient(capturing)
                .build();

        client.discover();

        TaxiiHttpRequest req = captured.get();
        assertNotNull(req);
        assertEquals("GET", req.method());
        assertEquals("https://example.invalid/taxii2/", req.uri().toString());
        assertEquals("application/taxii+json;version=2.1", req.headers().get("Accept"));
        assertTrue(req.headers().containsKey("Accept"));
        // No credentials supplied → no Authorization header.
        assertEquals(false, req.headers().containsKey("Authorization"));
    }
}
