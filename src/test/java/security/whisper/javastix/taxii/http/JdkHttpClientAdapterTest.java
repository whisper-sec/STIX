package security.whisper.javastix.taxii.http;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JdkHttpClientAdapterTest {

    private static WireMockServer server;
    private JdkHttpClientAdapter adapter;

    @BeforeAll
    static void start() {
        server = new WireMockServer(options().dynamicPort());
        server.start();
        WireMock.configureFor("localhost", server.port());
    }

    @AfterAll
    static void stop() {
        server.stop();
    }

    @BeforeEach
    void reset() {
        server.resetAll();
        adapter = new JdkHttpClientAdapter(Duration.ofSeconds(5));
    }

    @Test
    void sendsRequestAndReturnsResponseHeadersAndBody() throws Exception {
        stubFor(get(urlEqualTo("/x"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withHeader("X-TAXII-Date-Added-Last", "2024-01-15T00:00:00Z")
                        .withBody("{\"ok\":true}")));

        TaxiiHttpRequest req = TaxiiHttpRequest.builder()
                .uri(URI.create(server.baseUrl() + "/x"))
                .header("Accept", "application/taxii+json;version=2.1")
                .build();

        TaxiiHttpResponse resp = adapter.send(req);

        assertEquals(200, resp.statusCode());
        assertEquals("{\"ok\":true}", resp.body());
        assertTrue(resp.firstHeader("Content-Type").orElse("").contains("taxii+json"));
        assertEquals("2024-01-15T00:00:00Z",
                resp.firstHeader("X-TAXII-Date-Added-Last").orElseThrow());
    }

    @Test
    void caseInsensitiveHeaderLookup() throws Exception {
        stubFor(get(urlEqualTo("/h"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("X-TAXII-Date-Added-First", "2024-01-01T00:00:00Z")
                        .withBody("{}")));

        TaxiiHttpResponse resp = adapter.send(
                TaxiiHttpRequest.builder().uri(URI.create(server.baseUrl() + "/h")).build());

        assertTrue(resp.firstHeader("x-taxii-date-added-first").isPresent());
        assertTrue(resp.firstHeader("X-TAXII-DATE-ADDED-FIRST").isPresent());
    }

    @Test
    void forwardsCustomHeaders() throws Exception {
        stubFor(get(urlEqualTo("/hdr"))
                .withHeader("Accept", equalTo("application/taxii+json;version=2.1"))
                .withHeader("Authorization", equalTo("Basic dXNlcjpwYXNz"))
                .willReturn(aResponse().withStatus(200).withBody("{}")));

        TaxiiHttpResponse resp = adapter.send(TaxiiHttpRequest.builder()
                .uri(URI.create(server.baseUrl() + "/hdr"))
                .header("Accept", "application/taxii+json;version=2.1")
                .header("Authorization", "Basic dXNlcjpwYXNz")
                .build());

        assertEquals(200, resp.statusCode());
        verify(getRequestedFor(urlEqualTo("/hdr"))
                .withHeader("Authorization", equalTo("Basic dXNlcjpwYXNz")));
    }
}
