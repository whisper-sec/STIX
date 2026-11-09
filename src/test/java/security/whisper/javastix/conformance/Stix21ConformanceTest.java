package security.whisper.javastix.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.common.StixSpecVersion;
import security.whisper.javastix.coo.CyberObservableObject;
import security.whisper.javastix.coo.objects.DomainName;
import security.whisper.javastix.coo.objects.Ipv4Address;
import security.whisper.javastix.datamarkings.MarkingDefinition;
import security.whisper.javastix.datamarkings.objects.Statement;
import security.whisper.javastix.json.StixParserValidationException;
import security.whisper.javastix.json.StixParsers;
import security.whisper.javastix.meta.ExtensionDefinitionObject;
import security.whisper.javastix.meta.LanguageContentObject;
import security.whisper.javastix.sdo.objects.AttackPattern;
import security.whisper.javastix.sdo.objects.Campaign;
import security.whisper.javastix.sdo.objects.Grouping;
import security.whisper.javastix.sdo.objects.Identity;
import security.whisper.javastix.sdo.objects.Indicator;
import security.whisper.javastix.sdo.objects.Infrastructure;
import security.whisper.javastix.sdo.objects.Malware;
import security.whisper.javastix.sdo.objects.Note;
import security.whisper.javastix.sdo.objects.Opinion;
import security.whisper.javastix.sdo.objects.Report;
import security.whisper.javastix.sdo.objects.ThreatActor;
import security.whisper.javastix.sdo.objects.Vulnerability;
import security.whisper.javastix.sro.objects.Relationship;
import security.whisper.javastix.sro.objects.Sighting;
import security.whisper.javastix.taxii.TaxiiCursor;
import security.whisper.javastix.taxii.TaxiiPage;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * STIX 2.1 conformance of what the library writes and what it accepts: {@code spec_version} on
 * every object, identifier-only references, and no {@code spec_version} on bundles.
 */
@DisplayName("STIX 2.1 conformance: spec_version and references")
class Stix21ConformanceTest {

    private static final ObjectMapper MAPPER = StixParsers.getJsonMapper();
    private static final StixInstant T = new StixInstant(java.time.Instant.parse("2026-01-02T03:04:05.678Z"), 3);

    private static Identity identity() {
        return Identity.builder()
                .id("identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283")
                .created(T).modified(T)
                .name("ACME Corp")
                .identityClass("organization")
                .build();
    }

    private static Indicator indicator() {
        return Indicator.builder()
                .id("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
                .created(T).modified(T)
                .pattern("[ipv4-addr:value = '198.51.100.1']")
                .validFrom(T)
                .addLabel("malicious-activity")
                .build();
    }

    private static Infrastructure infrastructure() {
        return Infrastructure.builder()
                .id("infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d")
                .created(T).modified(T)
                .name("Example C2")
                .addInfrastructureType("command-and-control")
                .build();
    }

    /** One builder-made instance of every object the library writes that the OASIS schemas cover cleanly. */
    private static Map<String, BundleableObject> builtObjects() {
        Identity identity = identity();
        Indicator indicator = indicator();
        Infrastructure infrastructure = infrastructure();
        Map<String, BundleableObject> objects = new LinkedHashMap<>();
        objects.put("identity", identity);
        objects.put("indicator", indicator);
        objects.put("infrastructure", infrastructure);
        objects.put("attack-pattern", AttackPattern.builder().created(T).modified(T).name("Spear Phishing").build());
        objects.put("campaign", Campaign.builder().created(T).modified(T).name("Operation Example").build());
        objects.put("threat-actor", ThreatActor.builder().created(T).modified(T)
                .name("Example Actor").addThreatActorType("crime-syndicate").build());
        objects.put("vulnerability", Vulnerability.builder().created(T).modified(T).name("CVE-2016-1234").build());
        objects.put("note", Note.builder().created(T).modified(T)
                .content("Seen in the wild.").addObjectRef(indicator).addObjectRef(identity).build());
        objects.put("opinion", Opinion.builder().created(T).modified(T)
                .opinion("agree").addObjectRef(indicator).build());
        objects.put("grouping", Grouping.builder().created(T).modified(T)
                .context("suspicious-activity").addObjectRef(indicator).addObjectRef(infrastructure).build());
        objects.put("report", Report.builder().created(T).modified(T)
                .name("Example report").published(T).addLabel("threat-report").addObjectRef(indicator).build());
        objects.put("relationship", Relationship.builder().created(T).modified(T)
                .relationshipType("related-to").sourceRef(indicator).targetRef(infrastructure).build());
        objects.put("sighting", Sighting.builder().created(T).modified(T)
                .sightingOfRef(indicator).addWhereSightedRef(identity).build());
        objects.put("marking-definition", MarkingDefinition.builder().created(T)
                .definitionType("statement")
                .definition(Statement.builder().statement("Copyright 2026, Example Corp").build()).build());
        objects.put("domain-name", DomainName.builder().value("example.com").build());
        objects.put("ipv4-addr", Ipv4Address.builder().value("198.51.100.3").build());
        return objects;
    }

    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new TreeSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static JsonNode json(BundleableObject o) throws IOException {
        return MAPPER.readTree(o.toJsonString());
    }

    @Nested
    @DisplayName("emit")
    class Emit {

        @TestFactory
        @DisplayName("every object carries spec_version 2.1, right after type, and validates against the OASIS schema")
        Stream<DynamicTest> everyObjectCarriesSpecVersion() {
            return builtObjects().entrySet().stream().map(e -> DynamicTest.dynamicTest(e.getKey(), () -> {
                JsonNode node = json(e.getValue());
                assertEquals("2.1", node.path("spec_version").asText(), node.toString());
                Iterator<String> names = node.fieldNames();
                assertEquals("type", names.next());
                assertEquals("spec_version", names.next(), "spec_version should follow type: " + node);
                assertFalse(node.has("specVersion"), node.toString());
                Set<String> violations = OasisSchemas.violations(node);
                assertTrue(violations.isEmpty(), e.getKey() + " violates the OASIS schema: " + violations + "\n" + node);
            }));
        }

        @Test
        @DisplayName("an SDO the schema does not fully cover yet (Malware) still carries spec_version")
        void malwareCarriesSpecVersion() throws IOException {
            JsonNode node = json(Malware.builder().name("Example").addLabel("trojan").build());
            assertEquals("2.1", node.path("spec_version").asText());
        }

        @Test
        @DisplayName("language-content and extension-definition carry spec_version 2.1")
        void metaObjectsCarrySpecVersion() throws IOException {
            LanguageContentObject lc = LanguageContentObject.builder()
                    .id("language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d")
                    .created(T).modified(T)
                    .objectRef(indicator().getId()).objectModified(T)
                    .contents(Map.of("de", Map.of("name", "Beispiel")))
                    .build();
            assertEquals("2.1", json(lc).path("spec_version").asText());

            ExtensionDefinitionObject ed = ExtensionDefinitionObject.builder()
                    .id("extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62")
                    .created(T).modified(T)
                    .name("Example extension")
                    .schema("https://example.com/schema.json")
                    .version("1.0.0")
                    .addExtensionType("property-extension")
                    .build();
            assertEquals("2.1", json(ed).path("spec_version").asText());
        }

        @ParameterizedTest
        @ValueSource(strings = {"note", "opinion", "grouping", "report"})
        @DisplayName("object_refs is a list of identifiers, never embedded objects")
        void objectRefsAreIdentifiers(String type) throws IOException {
            JsonNode node = json(builtObjects().get(type));
            JsonNode refs = node.get("object_refs");
            assertTrue(refs.isArray() && refs.size() > 0, node.toString());
            refs.forEach(r -> {
                assertTrue(r.isTextual(), type + " object_refs holds a non-identifier: " + r);
                assertTrue(r.asText().matches("^[a-z][a-z0-9-]+--[0-9a-fA-F-]{36}$"), r.asText());
            });
        }

        @Test
        @DisplayName("a Note's object_refs name exactly the referenced objects")
        void noteRefsNameTheReferencedObjects() throws IOException {
            JsonNode refs = json(builtObjects().get("note")).get("object_refs");
            Set<String> ids = new TreeSet<>();
            refs.forEach(r -> ids.add(r.asText()));
            assertEquals(new TreeSet<>(Set.of(indicator().getId(), identity().getId())), ids);
        }

        @Test
        @DisplayName("object_marking_refs on language-content are identifiers")
        void metaMarkingRefsAreIdentifiers() throws IOException {
            MarkingDefinition tlp = (MarkingDefinition) builtObjects().get("marking-definition");
            LanguageContentObject lc = LanguageContentObject.builder()
                    .id("language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d")
                    .created(T).modified(T)
                    .objectRef(indicator().getId()).objectModified(T)
                    .contents(Map.of("de", Map.of("name", "Beispiel")))
                    .addObjectMarkingRef(tlp)
                    .build();
            JsonNode refs = json(lc).get("object_marking_refs");
            assertEquals(1, refs.size());
            assertEquals(tlp.getId(), refs.get(0).asText());
        }

        @Test
        @DisplayName("a bundle carries no spec_version (STIX 2.1 section 8) and validates against the schema")
        void bundleCarriesNoSpecVersion() throws IOException {
            Bundle.Builder b = Bundle.builder();
            builtObjects().values().forEach(b::addObject);
            JsonNode node = MAPPER.readTree(b.build().toJsonString());
            assertFalse(node.has("spec_version"), node.toString());
            assertEquals(Set.of("type", "id", "objects"), fieldNames(node));
            // Each object is checked against its own schema. The OASIS bundle.json does not list
            // grouping, incident, location, note or opinion, so for those its anyOf falls through to a
            // branch whose oneOf both core schemas match, and it rejects any bundle that holds one.
            for (JsonNode o : node.get("objects")) {
                assertEquals("2.1", o.path("spec_version").asText(), o.toString());
                Set<String> violations = OasisSchemas.violations(o);
                assertTrue(violations.isEmpty(), o.path("id") + " violates the OASIS schema: " + violations);
            }
        }
    }

    @Nested
    @DisplayName("accept")
    class Accept {

        @Test
        @DisplayName("spec_version is read as a first-class property, not a custom property")
        void specVersionIsFirstClass() throws Exception {
            String in = "{\"type\":\"indicator\",\"spec_version\":\"2.1\","
                    + "\"id\":\"indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f\","
                    + "\"created\":\"2016-04-06T20:03:48.000Z\",\"modified\":\"2016-04-06T20:03:48.000Z\","
                    + "\"labels\":[\"malicious-activity\"],\"pattern_type\":\"stix\","
                    + "\"pattern\":\"[domain-name:value = 'example.com']\","
                    + "\"valid_from\":\"2016-04-06T20:03:48Z\",\"x_example\":\"kept\"}";
            BundleableObject parsed = StixParsers.parseObject(in);
            assertInstanceOf(Indicator.class, parsed);
            assertEquals("2.1", ((StixSpecVersion) parsed).getSpecVersion());
            Map<String, Object> custom = ((StixCustomProperties) parsed).getCustomProperties();
            assertEquals(Map.of("x_example", "kept"), custom);

            JsonNode out = json(parsed);
            assertEquals("2.1", out.get("spec_version").asText());
            assertEquals("kept", out.get("x_example").asText());
        }

        @Test
        @DisplayName("an SCO with spec_version parses and keeps it")
        void scoSpecVersionIsFirstClass() throws Exception {
            BundleableObject parsed = StixParsers.parseObject(
                    "{\"type\":\"domain-name\",\"spec_version\":\"2.1\",\"value\":\"example.com\"}");
            assertInstanceOf(DomainName.class, parsed);
            assertEquals("2.1", ((StixSpecVersion) parsed).getSpecVersion());
            assertTrue(((StixCustomProperties) parsed).getCustomProperties().isEmpty());
        }

        @Test
        @DisplayName("an object read without spec_version is written as 2.1")
        void missingSpecVersionDefaultsTo21() throws Exception {
            ObjectNode in = (ObjectNode) json(indicator());
            in.remove("spec_version");
            JsonNode out = json(StixParsers.parseObject(in.toString()));
            assertEquals("2.1", out.get("spec_version").asText());
        }

        @Test
        @DisplayName("spec_version 2.0, which the OASIS schemas also allow, is accepted and kept")
        void specVersion20IsKept() throws Exception {
            ObjectNode in = (ObjectNode) json(indicator());
            in.put("spec_version", "2.0");
            JsonNode out = json(StixParsers.parseObject(in.toString()));
            assertEquals("2.0", out.get("spec_version").asText());
        }

        @ParameterizedTest
        @ValueSource(strings = {"2.2", "3.0", "2", "two point one", ""})
        @DisplayName("any other spec_version is rejected with an error that names it")
        void otherSpecVersionsAreRejected(String bad) throws IOException {
            ObjectNode in = (ObjectNode) json(indicator());
            in.put("spec_version", bad);
            StixParserValidationException e = assertThrows(StixParserValidationException.class,
                    () -> StixParsers.parseObject(in.toString()));
            assertTrue(e.getMessage().contains("specVersion"), e.getMessage());
        }

        @Test
        @DisplayName("a builder refuses a spec_version that is not a STIX version")
        void builderRejectsBadSpecVersion() {
            assertThrows(RuntimeException.class, () -> Indicator.builder()
                    .specVersion("9.9")
                    .pattern("[ipv4-addr:value = '198.51.100.1']")
                    .validFrom(T)
                    .addLabel("malicious-activity")
                    .build());
        }

        @ParameterizedTest
        @ValueSource(strings = {"note", "opinion", "grouping"})
        @DisplayName("identifier object_refs read back as references to the same ids and write back unchanged")
        void objectRefsRoundTrip(String type) throws Exception {
            JsonNode first = json(builtObjects().get(type));
            BundleableObject parsed = StixParsers.parseObject(first.toString());
            assertEquals(type, parsed.getType());
            JsonNode second = json(parsed);
            assertEquals(List.of(), JsonEquivalence.differences(first, second));
        }

        @Test
        @DisplayName("a STIX 2.0-style bundle that carries spec_version still parses")
        void bundleWithSpecVersionParses() throws Exception {
            ObjectNode in = (ObjectNode) MAPPER.readTree(Bundle.builder().addObject(indicator()).build().toJsonString());
            in.put("spec_version", "2.0");
            BundleObject bundle = StixParsers.parseBundle(in.toString());
            assertEquals("2.0", bundle.getSpecVersion());
            assertEquals(1, bundle.getObjects().size());
            assertFalse(MAPPER.readTree(bundle.toJsonString()).has("spec_version"));
        }

        @Test
        @DisplayName("a bundle-level spec_version that is not a STIX version is rejected")
        void bundleWithBadSpecVersionIsRejected() throws Exception {
            ObjectNode in = (ObjectNode) MAPPER.readTree(Bundle.builder().addObject(indicator()).build().toJsonString());
            in.put("spec_version", "9.9");
            assertThrows(StixParserValidationException.class, () -> StixParsers.parseBundle(in.toString()));
        }

        @Test
        @DisplayName("malformed JSON fails with the parser's own error, not a NullPointerException")
        void malformedJsonFailsClearly() {
            assertThrows(IOException.class, () -> StixParsers.parseObject("{\"type\": \"indicator\","));
            assertThrows(IOException.class, () -> StixParsers.parseBundle("not json"));
        }

        @Test
        @DisplayName("TaxiiPage.objects() reads a conformant STIX 2.1 page")
        void taxiiPageReadsConformantObjects() throws Exception {
            Identity identity = identity();
            Indicator indicator = indicator();
            Infrastructure infrastructure = infrastructure();
            List<BundleableObject> written = List.of(identity, indicator, infrastructure,
                    builtObjects().get("note"),
                    builtObjects().get("relationship"),
                    builtObjects().get("marking-definition"));
            Bundle.Builder b = Bundle.builder();
            written.forEach(b::addObject);
            String page = b.build().toJsonString();

            TaxiiPage taxiiPage = new TaxiiPage(page, false, TaxiiCursor.begin(), null, null);
            List<BundleableObject> read = taxiiPage.objects();
            assertEquals(written.stream().map(BundleableObject::getId).collect(Collectors.toSet()),
                    read.stream().map(BundleableObject::getId).collect(Collectors.toSet()));
            for (BundleableObject o : read) {
                assertEquals("2.1", ((StixSpecVersion) o).getSpecVersion(), o.getId());
            }
            assertEquals(written.size(), taxiiPage.bundle().getObjects().size());
        }
    }

    @Test
    @DisplayName("each built SDO, SRO and marking round-trips through the parser unchanged")
    void builtObjectsRoundTrip() throws Exception {
        List<String> problems = new ArrayList<>();
        for (Map.Entry<String, BundleableObject> e : builtObjects().entrySet()) {
            if (e.getValue() instanceof CyberObservableObject) {
                continue; // reading an SCO's id back is a listed gap (known-gaps.txt)
            }
            JsonNode first = json(e.getValue());
            JsonNode second = json(StixParsers.parseObject(first.toString()));
            List<String> diffs = JsonEquivalence.differences(first, second);
            if (!diffs.isEmpty()) {
                problems.add(e.getKey() + ": " + diffs);
            }
        }
        assertTrue(problems.isEmpty(), String.join("\n", problems));
    }
}
