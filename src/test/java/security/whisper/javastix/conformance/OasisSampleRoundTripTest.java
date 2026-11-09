package security.whisper.javastix.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.custom.objects.CustomObject;
import security.whisper.javastix.json.StixParsers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trips real, conformant STIX 2.1 content through the library: parse, serialise again,
 * and require the output to be equivalent to the input and valid against the official OASIS
 * JSON schemas.
 *
 * <p>Two corpora are used, both vendored under {@code src/test/resources/stix/oasis}:
 * <ul>
 *   <li>{@code spec-2.1-examples.json}: the JSON examples from the STIX 2.1 OASIS Standard
 *       (stix-v2.1-os), grouped by type, keeping only those that validate against the OASIS
 *       schemas.</li>
 *   <li>{@code examples/}: the example bundles published in oasis-open/cti-stix2-json-schemas.</li>
 * </ul>
 *
 * <p>Some samples still exercise parts of STIX 2.1 the library does not model yet. Those are
 * listed, with the reason, in {@code known-gaps.txt}. The list is a ratchet: a listed sample must
 * still fail (so fixing a gap forces its entry out of the list), and every sample not listed must
 * round-trip cleanly. Whatever the gap, no sample may be rejected because of {@code spec_version}.
 */
@DisplayName("STIX 2.1 round-trip against OASIS samples")
class OasisSampleRoundTripTest {

    private static final ObjectMapper MAPPER = StixParsers.getJsonMapper();

    /** The example bundles published alongside the OASIS schemas. */
    private static final List<String> EXAMPLE_BUNDLES = List.of(
            "indicator-for-c2-ip-address.json",
            "indicator-to-campaign-relationship.json",
            "indicators-for-C2-with-COA.json",
            "infrastructure.json",
            "malicious-email-indicator-with-attachment.json",
            "apt1.json",
            "poisonivy.json");

    /** The single-object example published alongside the OASIS schemas. */
    private static final String EXAMPLE_OBJECT = "interop-objectmarking-test.json";

    static JsonNode resource(String path) throws IOException {
        try (InputStream in = OasisSampleRoundTripTest.class.getResourceAsStream("/stix/oasis/" + path)) {
            assertNotNull(in, "missing test resource " + path);
            return MAPPER.readTree(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /** Every sample, keyed by a stable label: {@code <type> #<n> <id>} or the example file name. */
    static Map<String, JsonNode> samples() throws IOException {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> types = resource("spec-2.1-examples.json").fields();
        while (types.hasNext()) {
            Map.Entry<String, JsonNode> type = types.next();
            int i = 0;
            for (JsonNode example : type.getValue()) {
                out.put(type.getKey() + " #" + (++i) + " " + example.path("id").asText(), example);
            }
        }
        out.put(EXAMPLE_OBJECT, resource("examples/" + EXAMPLE_OBJECT));
        for (String name : EXAMPLE_BUNDLES) {
            out.put(name, resource("examples/" + name));
        }
        return out;
    }

    /** Label to reason, from {@code known-gaps.txt} ({@code label | reason}, {@code #} comments). */
    static Map<String, String> knownGaps() throws IOException {
        Map<String, String> gaps = new LinkedHashMap<>();
        try (InputStream in = OasisSampleRoundTripTest.class.getResourceAsStream("/stix/oasis/known-gaps.txt")) {
            assertNotNull(in, "missing test resource known-gaps.txt");
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                int bar = line.indexOf('|');
                assertTrue(bar > 0, "known-gaps.txt line has no '|': " + line);
                gaps.put(line.substring(0, bar).trim(), line.substring(bar + 1).trim());
            }
        }
        return gaps;
    }

    @TestFactory
    @DisplayName("every sample round-trips to equivalent, schema-valid JSON, except the listed known gaps")
    Stream<DynamicTest> samplesRoundTrip() throws IOException {
        Map<String, String> gaps = knownGaps();
        return samples().entrySet().stream().map(sample -> DynamicTest.dynamicTest(sample.getKey(), () -> {
            Optional<String> failure = roundTripFailure(sample.getValue());
            failure.ifPresent(f -> assertFalse(blamesSpecVersion(f),
                    sample.getKey() + " failed because of spec_version: " + f));
            String gap = gaps.get(sample.getKey());
            if (gap == null) {
                assertTrue(failure.isEmpty(), sample.getKey() + ": " + failure.orElse(""));
            } else {
                assertTrue(failure.isPresent(), sample.getKey()
                        + " now round-trips cleanly; remove it from known-gaps.txt (was: " + gap + ")");
            }
        }));
    }

    @Test
    @DisplayName("known-gaps.txt names only samples that exist")
    void knownGapsAreReal() throws IOException {
        Set<String> labels = samples().keySet();
        List<String> stale = knownGaps().keySet().stream()
                .filter(label -> !labels.contains(label))
                .collect(Collectors.toList());
        assertTrue(stale.isEmpty(), "known-gaps.txt names samples that do not exist: " + stale);
    }

    @Test
    @DisplayName("every sample that parses is written back with its spec_version")
    void parsedSamplesKeepSpecVersion() throws IOException {
        List<String> problems = new ArrayList<>();
        for (Map.Entry<String, JsonNode> sample : samples().entrySet()) {
            JsonNode input = sample.getValue();
            List<JsonNode> objects = new ArrayList<>();
            try {
                if ("bundle".equals(input.path("type").asText())) {
                    JsonNode emitted = MAPPER.readTree(StixParsers.parseBundle(input.toString()).toJsonString());
                    if (emitted.has("spec_version")) {
                        problems.add(sample.getKey() + ": bundle carries spec_version");
                    }
                    emitted.path("objects").forEach(objects::add);
                } else {
                    objects.add(MAPPER.readTree(StixParsers.parseObject(input.toString()).toJsonString()));
                }
            } catch (Exception notParsedYet) {
                continue; // a known gap; samplesRoundTrip holds it to account
            }
            for (JsonNode o : objects) {
                if (!"2.1".equals(o.path("spec_version").asText())) {
                    problems.add(sample.getKey() + ": " + o.path("id").asText() + " has spec_version "
                            + o.path("spec_version"));
                }
            }
        }
        assertTrue(problems.isEmpty(), String.join("\n", problems));
    }

    /** True when a failure is about {@code spec_version} itself, not merely mentions it. */
    static boolean blamesSpecVersion(String failure) {
        return failure.contains("[spec_version]")      // landed in custom properties
                || failure.contains("specVersion:")     // failed bean validation
                || failure.contains(".spec_version:");  // differs after the round-trip
    }

    /**
     * Parses the sample, serialises it again and compares; empty when the round-trip is clean.
     */
    static Optional<String> roundTripFailure(JsonNode input) {
        try {
            JsonNode emitted;
            if ("bundle".equals(input.path("type").asText())) {
                BundleObject bundle = StixParsers.parseBundle(input.toString());
                emitted = MAPPER.readTree(bundle.toJsonString());
            } else {
                BundleableObject parsed = StixParsers.parseObject(input.toString());
                assertEquals(input.path("type").asText(), parsed.getType());
                if (parsed instanceof CustomObject) {
                    return Optional.of("parsed as a generic custom object instead of its STIX type");
                }
                emitted = MAPPER.readTree(parsed.toJsonString());
            }
            List<String> diffs = JsonEquivalence.differences(input, emitted);
            if (!diffs.isEmpty()) {
                return Optional.of("differs after round-trip: " + String.join("; ", diffs));
            }
            Set<String> violations = OasisSchemas.violations(emitted);
            if (!violations.isEmpty()) {
                return Optional.of("emitted JSON violates the OASIS schema: " + violations);
            }
            return Optional.empty();
        } catch (Exception | AssertionError e) {
            return Optional.of("rejected: " + e);
        }
    }
}
