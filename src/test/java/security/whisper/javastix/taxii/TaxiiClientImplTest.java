package security.whisper.javastix.taxii;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.taxii.exception.TaxiiAuthException;
import security.whisper.javastix.taxii.exception.TaxiiException;
import security.whisper.javastix.taxii.exception.TaxiiNotFoundException;
import security.whisper.javastix.taxii.exception.TaxiiProtocolException;
import security.whisper.javastix.taxii.exception.TaxiiServerException;
import security.whisper.javastix.taxii.model.ApiRoot;
import security.whisper.javastix.taxii.model.Collection;
import security.whisper.javastix.taxii.model.Discovery;
import security.whisper.javastix.taxii.model.Manifest;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaxiiClientImplTest {

    private static WireMockServer server;
    private TaxiiClient client;

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
        client = TaxiiClient.builder()
                .baseUrl(server.baseUrl() + "/")
                .credentials("guest", "guest")
                .build();
    }

    private static String fixture(String name) throws IOException, URISyntaxException {
        Path p = Paths.get(TaxiiClientImplTest.class
                .getResource("/taxii/" + name).toURI());
        return Files.readString(p);
    }

    // --- discovery -------------------------------------------------------

    @Test
    void discover_parsesCanonicalResponse() throws Exception {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("discovery.json"))));

        Discovery d = client.discover();

        assertEquals("Some TAXII Server", d.getTitle());
        assertEquals(3, d.getApiRoots().size());
        assertEquals("https://taxii.example.com/api2/", d.getDefaultApiRoot().orElseThrow());
    }

    @Test
    void discover_sendsBasicAuthAndTaxiiAcceptHeader() throws Exception {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("discovery.json"))));

        client.discover();

        verify(getRequestedFor(urlEqualTo("/taxii2/"))
                .withHeader("Accept", equalTo("application/taxii+json;version=2.1"))
                .withHeader("Authorization", equalTo("Basic Z3Vlc3Q6Z3Vlc3Q=")));
    }

    // --- api root --------------------------------------------------------

    @Test
    void apiRoot_recordsPathOnReturnedObject() throws Exception {
        stubFor(get(urlEqualTo("/api1/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("api-root.json"))));

        ApiRoot root = client.apiRoot("api1/");

        assertEquals("api1/", root.getPath());
        assertEquals("Malware Research Group", root.getTitle());
        assertEquals(List.of("application/taxii+json;version=2.1"), root.getVersions());
    }

    @Test
    void apiRoot_acceptsLeadingSlash() throws Exception {
        stubFor(get(urlEqualTo("/api1/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("api-root.json"))));

        ApiRoot root = client.apiRoot("/api1");
        assertEquals("api1/", root.getPath());
    }

    // --- collections -----------------------------------------------------

    @Test
    void collections_returnsList() throws Exception {
        stubFor(get(urlEqualTo("/api1/")).willReturn(aResponse().withStatus(200)
                .withHeader("Content-Type", "application/taxii+json;version=2.1")
                .withBody(fixture("api-root.json"))));
        stubFor(get(urlEqualTo("/api1/collections/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("collections.json"))));

        ApiRoot root = client.apiRoot("api1");
        List<Collection> cols = client.collections(root);

        assertEquals(2, cols.size());
        assertEquals("91a7b528-80eb-42ed-a74d-c6fbd5a26116", cols.get(0).getId());
        assertTrue(cols.get(0).canRead());
        assertFalse(cols.get(0).canWrite());
    }

    @Test
    void collection_byId_returnsSingleCollection() throws Exception {
        stubFor(get(urlEqualTo("/api1/")).willReturn(aResponse().withStatus(200)
                .withHeader("Content-Type", "application/taxii+json;version=2.1")
                .withBody(fixture("api-root.json"))));
        stubFor(get(urlEqualTo("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("collection.json"))));

        ApiRoot root = client.apiRoot("api1");
        Collection col = client.collection(root, "91a7b528-80eb-42ed-a74d-c6fbd5a26116");

        assertEquals("high-value-indicators", col.getAlias().orElseThrow());
    }

    // --- objects + pagination -------------------------------------------

    @Test
    void objects_firstPage_sendsNoAddedAfter_returnsParseableBundle() throws Exception {
        stubFor(get(urlEqualTo("/api1/")).willReturn(aResponse().withStatus(200)
                .withHeader("Content-Type", "application/taxii+json;version=2.1")
                .withBody(fixture("api-root.json"))));
        stubFor(get(urlPathEqualTo("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withHeader("X-TAXII-Date-Added-First", "2024-01-15T10:00:00Z")
                        .withHeader("X-TAXII-Date-Added-Last", "2024-01-15T10:05:00Z")
                        .withBody(fixture("objects-page1.json"))));

        ApiRoot root = client.apiRoot("api1");
        Collection col = new Collection(
                "91a7b528-80eb-42ed-a74d-c6fbd5a26116", "t", null, null, true, false, List.of());

        TaxiiPage page = client.objects(root, col, TaxiiCursor.begin(), TaxiiFilter.none());

        verify(getRequestedFor(
                urlEqualTo("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/")));
        assertTrue(page.hasMore());
        assertEquals(Instant.parse("2024-01-15T10:05:00Z"),
                page.dateAddedLast().orElseThrow());

        BundleObject bundle = page.bundle();
        assertNotNull(bundle);
        assertEquals(2, bundle.getObjects().size());
    }

    @Test
    void objects_secondPage_sendsAddedAfterFromPreviousPage() throws Exception {
        stubFor(get(urlEqualTo("/api1/")).willReturn(aResponse().withStatus(200)
                .withHeader("Content-Type", "application/taxii+json;version=2.1")
                .withBody(fixture("api-root.json"))));
        stubFor(get(urlEqualTo("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withHeader("X-TAXII-Date-Added-Last", "2024-01-15T10:05:00Z")
                        .withBody(fixture("objects-page1.json"))));
        stubFor(get(urlMatching("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/\\?.*"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withHeader("X-TAXII-Date-Added-Last", "2024-01-15T11:00:00Z")
                        .withBody(fixture("objects-page2.json"))));

        ApiRoot root = client.apiRoot("api1");
        Collection col = new Collection(
                "91a7b528-80eb-42ed-a74d-c6fbd5a26116", "t", null, null, true, false, List.of());

        TaxiiPage p1 = client.objects(root, col, TaxiiCursor.begin(), TaxiiFilter.none());
        TaxiiPage p2 = client.objects(root, col, p1.nextCursor(), TaxiiFilter.none());

        assertFalse(p2.hasMore());
        verify(getRequestedFor(urlMatching(
                "/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/\\?added_after=2024-01-15T10%3A05%3A00Z(&next=.*)?")));
    }

    @Test
    void objects_appliesMatchTypeFilter() throws Exception {
        stubFor(get(urlEqualTo("/api1/")).willReturn(aResponse().withStatus(200)
                .withHeader("Content-Type", "application/taxii+json;version=2.1")
                .withBody(fixture("api-root.json"))));
        stubFor(get(urlMatching("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/\\?match\\[type\\]=indicator%2Cmalware"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("objects-page1.json"))));

        ApiRoot root = client.apiRoot("api1");
        Collection col = new Collection(
                "91a7b528-80eb-42ed-a74d-c6fbd5a26116", "t", null, null, true, false, List.of());

        TaxiiFilter filter = TaxiiFilter.builder()
                .addType("indicator")
                .addType("malware")
                .build();
        client.objects(root, col, TaxiiCursor.begin(), filter);

        verify(getRequestedFor(urlMatching(
                "/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/objects/\\?match\\[type\\]=indicator%2Cmalware")));
    }

    @Test
    void objects_byAbsoluteUrl_followsNextLinkLiterally() throws Exception {
        stubFor(get(urlEqualTo("/server-provided-page"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("objects-page2.json"))));

        TaxiiPage p = client.objects(URI.create(server.baseUrl() + "/server-provided-page"));
        assertFalse(p.hasMore());
    }

    @Test
    void objects_absoluteUrl_rejectsRelative() {
        assertThrows(IllegalArgumentException.class,
                () -> client.objects(URI.create("/relative")));
    }

    @Test
    void objects_morePageMissingPaginationState_throwsProtocol() throws Exception {
        stubFor(get(urlEqualTo("/p/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody("{\"more\":true,\"objects\":[]}")));

        assertThrows(TaxiiProtocolException.class,
                () -> client.objects(URI.create(server.baseUrl() + "/p/")));
    }

    @Test
    void objects_emptyEnvelopeMoreFalse_returnsEmptyObjects() throws Exception {
        stubFor(get(urlEqualTo("/empty"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody("{\"more\":false,\"objects\":[]}")));

        TaxiiPage p = client.objects(URI.create(server.baseUrl() + "/empty"));
        assertFalse(p.hasMore());
        // STIX Bundle requires @Size(min=1), so .bundle() is not callable for
        // empty pages - .objects() handles them.
        assertTrue(p.objects().isEmpty());
    }

    // --- manifest --------------------------------------------------------

    @Test
    void manifest_parsesRecords() throws Exception {
        stubFor(get(urlEqualTo("/api1/")).willReturn(aResponse().withStatus(200)
                .withHeader("Content-Type", "application/taxii+json;version=2.1")
                .withBody(fixture("api-root.json"))));
        stubFor(get(urlEqualTo("/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/manifest/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("manifest.json"))));

        ApiRoot root = client.apiRoot("api1");
        Collection col = new Collection(
                "91a7b528-80eb-42ed-a74d-c6fbd5a26116", "t", null, null, true, false, List.of());

        Manifest m = client.manifest(root, col, TaxiiCursor.begin(), TaxiiFilter.none());

        assertEquals(2, m.getObjects().size());
        assertFalse(m.isMore());
        assertEquals(Instant.parse("2016-11-01T03:04:05Z"),
                m.getObjects().get(0).getDateAdded());
    }

    // --- error mapping ---------------------------------------------------

    @Test
    void status401_mapsToAuthException() throws Exception {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse().withStatus(401)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("error-401.json"))));

        TaxiiAuthException ex = assertThrows(TaxiiAuthException.class,
                () -> client.discover());
        assertEquals(401, ex.getHttpStatus());
        assertTrue(ex.getMessage().contains("Authorization required"));
    }

    @Test
    void status403_alsoMapsToAuthException() {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse().withStatus(403)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody("{}")));

        TaxiiAuthException ex = assertThrows(TaxiiAuthException.class,
                () -> client.discover());
        assertEquals(403, ex.getHttpStatus());
    }

    @Test
    void status404_mapsToNotFound() {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse().withStatus(404)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody("{}")));

        assertThrows(TaxiiNotFoundException.class, () -> client.discover());
    }

    @Test
    void status500_mapsToServerException() throws Exception {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse().withStatus(500)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody(fixture("error-500.json"))));

        TaxiiServerException ex = assertThrows(TaxiiServerException.class,
                () -> client.discover());
        assertEquals(500, ex.getHttpStatus());
    }

    @Test
    void status418_mapsToGenericTaxiiException() {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse().withStatus(418)
                        .withHeader("Content-Type", "application/taxii+json;version=2.1")
                        .withBody("{}")));

        TaxiiException ex = assertThrows(TaxiiException.class, () -> client.discover());
        assertEquals(418, ex.getHttpStatus());
    }

    @Test
    void unexpectedContentType_throwsProtocolException() {
        stubFor(get(urlEqualTo("/taxii2/"))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody("<html/>")));

        assertThrows(TaxiiProtocolException.class, () -> client.discover());
    }

    // --- builder ---------------------------------------------------------

    @Test
    void builder_baseUrlRequired() {
        assertThrows(IllegalStateException.class, () -> TaxiiClient.builder().build());
    }
}
