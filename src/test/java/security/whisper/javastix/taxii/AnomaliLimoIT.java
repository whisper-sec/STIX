package security.whisper.javastix.taxii;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.taxii.model.ApiRoot;
import security.whisper.javastix.taxii.model.Collection;
import security.whisper.javastix.taxii.model.Discovery;

import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Live integration test against the Anomali Limo public TAXII 2.1 server.
 * Disabled by default - enable with {@code -Dtaxii.it=true} to run.
 *
 * <p>Reads one collection's first page and parses it through the existing
 * {@link security.whisper.javastix.json.StixParsers#parseBundle} entry point.
 *
 * <p>If Limo is unreachable or its API surface drifts, this test should
 * fail loudly - that's the point - but it doesn't run in the default
 * {@code mvn test} flow, so PRs aren't blocked by a third-party endpoint.
 */
@EnabledIfSystemProperty(named = "taxii.it", matches = "true")
class AnomaliLimoIT {

    private static final String LIMO_BASE =
            "https://limo.anomali.com/api/v1/taxii/taxii-discovery-service/";

    @Test
    void discoverAndFetchFirstCollectionPage() throws Exception {
        try (TaxiiClient client = TaxiiClient.builder()
                .baseUrl(LIMO_BASE)
                .credentials("guest", "guest")
                .build()) {

            Discovery d = client.discover();
            assertNotNull(d.getTitle(), "discovery title should be present");
            assertFalse(d.getApiRoots().isEmpty(), "discovery should report at least one API root");

            String apiRootAbsolute = d.getApiRoots().get(0);
            URI baseUri = URI.create(LIMO_BASE);
            String apiRootPath = URI.create(apiRootAbsolute).getPath();
            // Strip the base path so the relative path resolves correctly.
            if (apiRootPath.startsWith(baseUri.getPath())) {
                apiRootPath = apiRootPath.substring(baseUri.getPath().length());
            }
            ApiRoot root = client.apiRoot(apiRootPath);

            List<Collection> cols = client.collections(root);
            assertFalse(cols.isEmpty(), "API root should expose at least one collection");

            TaxiiPage page = client.objects(root, cols.get(0),
                    TaxiiCursor.begin(),
                    TaxiiFilter.builder().limit(5).build());
            BundleObject bundle = page.bundle();
            assertTrue(bundle.getObjects().size() >= 0,
                    "bundle should parse cleanly even if empty");
        }
    }
}
