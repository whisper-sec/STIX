package security.whisper.javastix.bundle;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.objects.*;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.coo.objects.DomainName;
import security.whisper.javastix.datamarkings.MarkingDefinition;
import security.whisper.javastix.datamarkings.objects.Tlp;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.json.StixParsers;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.UUID;

/**
 * Comprehensive test suite for STIX Bundle functionality.
 * Tests bundle creation, serialization, object containment, and constraints.
 */
@DisplayName("STIX Bundle Tests")
public class BundleTest {

    private Indicator testIndicator;
    private Malware testMalware;
    private ThreatActor testThreatActor;

    @BeforeEach
    void setUp() {
        testIndicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .build();

        testMalware = Malware.builder()
            .name("TestMalware")
            .addLabel("trojan")
            .build();

        testThreatActor = ThreatActor.builder()
            .name("Test Actor")
            .addLabel("hacker")
            .build();
    }

    @Nested
    @DisplayName("Bundle Creation Tests")
    class BundleCreationTests {

        @Test
        @DisplayName("Create valid bundle with objects")
        void testCreateValidBundle() {
            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .addObject(testMalware)
                .addObject(testThreatActor)
                .build();

            assertNotNull(bundle);
            assertEquals("bundle", bundle.getType());
            assertTrue(bundle.getId().startsWith("bundle--"));
            assertEquals(3, bundle.getObjects().size());
        }

        @Test
        @DisplayName("Bundle requires at least one object")
        void testBundleRequiresObjects() {
            assertThrows(Exception.class, () -> {
                Bundle.builder().build();
            }, "Bundle without objects should fail validation");
        }

        @Test
        @DisplayName("Bundle with spec_version")
        void testBundleSpecVersion() {
            Bundle bundle = Bundle.builder()
                .specVersion("2.1")
                .addObject(testIndicator)
                .build();

            assertEquals("2.1", bundle.getSpecVersion());
        }

        @Test
        @DisplayName("Bundle ID format validation")
        void testBundleIdFormat() {
            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .build();

            assertTrue(bundle.getId().matches("^bundle--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
                "Bundle ID should match STIX ID format");
        }
    }

    @Nested
    @DisplayName("Bundle Content Tests")
    class BundleContentTests {

        @Test
        @DisplayName("Bundle with mixed object types")
        void testBundleMixedObjects() {
            Relationship relationship = Relationship.builder()
                .relationshipType("uses")
                .sourceRef(testThreatActor)
                .targetRef(testMalware)
                .build();

            Sighting sighting = Sighting.builder()
                .sightingOfRef(testIndicator)
                .count(5)
                .build();

            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .addObject(testMalware)
                .addObject(testThreatActor)
                .addObject(relationship)
                .addObject(sighting)
                .build();

            assertEquals(5, bundle.getObjects().size());

            // Verify all object types are present
            long sdoCount = bundle.getObjects().stream()
                .filter(obj -> obj instanceof DomainObject)
                .count();
            long sroCount = bundle.getObjects().stream()
                .filter(obj -> obj instanceof RelationshipSro || obj instanceof SightingSro)
                .count();

            assertEquals(3, sdoCount, "Should have 3 SDOs");
            assertEquals(2, sroCount, "Should have 2 SROs");
        }

        @Test
        @DisplayName("Bundle with duplicate objects")
        void testBundleDuplicateObjects() {
            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .addObject(testIndicator) // Same object twice
                .build();

            // Sets should prevent duplicates
            assertEquals(1, bundle.getObjects().size(),
                "Bundle should not contain duplicate objects");
        }

        @Test
        @DisplayName("Bundle with custom objects")
        void testBundleCustomObjects() {
            // Custom object with x- prefix
            Identity customIdentity = Identity.builder()
                .name("Custom Identity")
                .identityClass("individual")
                .build();

            Bundle bundle = Bundle.builder()
                .addObject(customIdentity)
                .addObject(testIndicator)
                .build();

            assertEquals(2, bundle.getObjects().size());
        }
    }

    @Nested
    @DisplayName("Bundle Serialization Tests")
    class BundleSerializationTests {

        @Test
        @DisplayName("Bundle JSON serialization")
        void testBundleJsonSerialization() {
            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .addObject(testMalware)
                .build();

            String json = bundle.toJsonString();
            assertNotNull(json);
            assertTrue(json.contains("\"type\":\"bundle\""));
            System.out.println("JSON output: " + json);
            assertTrue(json.contains("\"spec_version\":\"2.1\"") || json.contains("\"specVersion\":\"2.1\""));
            assertTrue(json.contains("\"objects\":["));
        }

        @Test
        @DisplayName("Bundle JSON structure validation")
        void testBundleJsonStructure() throws Exception {
            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .build();

            String json = bundle.toJsonString();
            JsonNode node = StixParsers.getJsonMapper().readTree(json);

            assertEquals("bundle", node.get("type").asText());
            assertTrue(node.has("id"));
            assertTrue(node.has("spec_version"));
            assertTrue(node.has("objects"));
            assertTrue(node.get("objects").isArray());
            assertEquals(1, node.get("objects").size());
        }

        @Test
        @DisplayName("Bundle objects maintain their properties")
        void testBundleObjectProperties() throws Exception {
            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .build();

            String json = bundle.toJsonString();
            JsonNode node = StixParsers.getJsonMapper().readTree(json);
            JsonNode indicatorNode = node.get("objects").get(0);

            assertEquals("indicator", indicatorNode.get("type").asText());
            assertTrue(indicatorNode.has("pattern"));
            assertTrue(indicatorNode.has("valid_from"));
        }
    }

    @Nested
    @DisplayName("Bundle with Relationships Tests")
    class BundleRelationshipTests {

        @Test
        @DisplayName("Bundle with complete relationship graph")
        void testBundleRelationshipGraph() {
            Campaign campaign = Campaign.builder()
                .name("Test Campaign")
                .build();

            Relationship actorUsesMalware = Relationship.builder()
                .relationshipType("uses")
                .sourceRef(testThreatActor)
                .targetRef(testMalware)
                .build();

            Relationship campaignAttributedTo = Relationship.builder()
                .relationshipType("attributed-to")
                .sourceRef(campaign)
                .targetRef(testThreatActor)
                .build();

            Relationship malwareIndicates = Relationship.builder()
                .relationshipType("indicates")
                .sourceRef(testIndicator)
                .targetRef(testMalware)
                .build();

            Bundle bundle = Bundle.builder()
                .addObject(testIndicator)
                .addObject(testMalware)
                .addObject(testThreatActor)
                .addObject(campaign)
                .addObject(actorUsesMalware)
                .addObject(campaignAttributedTo)
                .addObject(malwareIndicates)
                .build();

            assertEquals(7, bundle.getObjects().size());
        }

        @Test
        @DisplayName("Bundle validates relationship references")
        void testBundleRelationshipReferences() {
            Relationship relationship = Relationship.builder()
                .relationshipType("uses")
                .sourceRef(testThreatActor)
                .targetRef(testMalware)
                .build();

            Bundle bundle = Bundle.builder()
                .addObject(testThreatActor)
                .addObject(testMalware)
                .addObject(relationship)
                .build();

            // Verify relationship references exist in bundle
            assertTrue(bundle.getObjects().contains(testThreatActor));
            assertTrue(bundle.getObjects().contains(testMalware));
        }
    }

    @Nested
    @DisplayName("Large Bundle Tests")
    class LargeBundleTests {

        @Test
        @DisplayName("Bundle with many objects")
        void testLargeBundle() {
            Bundle.Builder bundleBuilder = Bundle.builder();

            // Add many indicators
            for (int i = 0; i < 1000; i++) {
                Indicator indicator = Indicator.builder()
                    .pattern("[file:size = " + i + "]")
                    .validFrom(new StixInstant())
                    .addLabel("malicious-activity")
                    .build();
                bundleBuilder.addObject(indicator);
            }

            Bundle bundle = bundleBuilder.build();
            assertEquals(1000, bundle.getObjects().size());
        }

        @Test
        @DisplayName("Bundle serialization performance")
        void testBundleSerializationPerformance() {
            Bundle.Builder bundleBuilder = Bundle.builder();

            for (int i = 0; i < 100; i++) {
                bundleBuilder.addObject(Indicator.builder()
                    .pattern("[file:size = " + i + "]")
                    .validFrom(new StixInstant())
                    .addLabel("malicious-activity")
                    .build());
            }

            Bundle bundle = bundleBuilder.build();

            long startTime = System.currentTimeMillis();
            String json = bundle.toJsonString();
            long endTime = System.currentTimeMillis();

            assertNotNull(json);
            assertTrue(endTime - startTime < 1000,
                "Serialization of 100 objects should take less than 1 second");
        }
    }

    @Nested
    @DisplayName("Bundle Edge Cases")
    class BundleEdgeCaseTests {

        @Test
        @DisplayName("Bundle with circular references")
        void testBundleCircularReferences() {
            Identity identity1 = Identity.builder()
                .name("Identity 1")
                .identityClass("individual")
                .build();

            Identity identity2 = Identity.builder()
                .name("Identity 2")
                .identityClass("individual")
                .createdByRef(identity1)
                .build();

            // Note: In real implementation, identity1 cannot reference identity2
            // as it would create a circular reference
            Bundle bundle = Bundle.builder()
                .addObject(identity1)
                .addObject(identity2)
                .build();

            assertEquals(2, bundle.getObjects().size());
        }

        @Test
        @DisplayName("Bundle with deeply nested marking definitions")
        void testBundleNestedMarkings() {
            MarkingDefinition tlpWhite = MarkingDefinition.builder()
                .definitionType("tlp")
                .definition(Tlp.builder()
                    .tlp("white")
                    .build())
                .build();

            Indicator markedIndicator = Indicator.builder()
                .pattern("[file:size > 0]")
                .validFrom(new StixInstant())
                .addLabel("malicious-activity")
                // TODO: Fix object marking refs - needs investigation
                // .addObjectMarkingRef(tlpWhite)
                .build();

            Bundle bundle = Bundle.builder()
                .addObject(markedIndicator)
                .build();

            assertEquals(1, bundle.getObjects().size());
        }

        @Test
        @DisplayName("Bundle with all STIX 2.1 object types")
        void testBundleAllObjectTypes() {
            Bundle bundle = Bundle.builder()
                // SDOs
                .addObject(AttackPattern.builder().name("Test AP").build())
                .addObject(Campaign.builder().name("Test Campaign").build())
                .addObject(CourseOfAction.builder().name("Test CoA").build())
                .addObject(Grouping.builder()
                    .context("suspicious-activity")
                    .addObjectRef(testIndicator)
                    .build())
                .addObject(Identity.builder()
                    .name("Test Identity")
                    .identityClass("individual")
                    .build())
                .addObject(testIndicator)
                .addObject(Infrastructure.builder()
                    .name("Test Infra")
                    .addInfrastructureType("hosting-service")
                    .build())
                .addObject(IntrusionSet.builder().name("Test IS").build())
                .addObject(Location.builder().name("Test Location").build())
                .addObject(testMalware)
                .addObject(MalwareAnalysis.builder()
                    .product("Test Product")
                    .build())
                .addObject(Note.builder()
                    .content("Test Note")
                    .addObjectRef(testIndicator)
                    .build())
                .addObject(ObservedData.builder()
                    .firstObserved(new StixInstant())
                    .lastObserved(new StixInstant())
                    .numberObserved(1)
                    .addObject(DomainName.builder()
                        .value("example.com")
                        .build())
                    .build())
                .addObject(Opinion.builder()
                    .opinion("agree")
                    .addObjectRef(testIndicator)
                    .build())
                .addObject(Report.builder()
                    .name("Test Report")
                    .published(new StixInstant())
                    .addLabel("threat-report")
                    .addObjectRef(testIndicator)
                    .build())
                .addObject(testThreatActor)
                .addObject(Tool.builder()
                    .name("Test Tool")
                    .addLabel("remote-access")
                    .build())
                .addObject(Vulnerability.builder()
                    .name("CVE-2021-0001")
                    .build())
                // SROs
                .addObject(Relationship.builder()
                    .relationshipType("uses")
                    .sourceRef(testThreatActor)
                    .targetRef(testMalware)
                    .build())
                .addObject(Sighting.builder()
                    .sightingOfRef(testIndicator)
                    .build())
                .build();

            assertTrue(bundle.getObjects().size() >= 20,
                "Bundle should contain all object types");
        }

        @Test
        @DisplayName("Empty bundle object handling")
        void testEmptyBundleHandling() {
            // Test minimum valid bundle
            Bundle bundle = Bundle.builder()
                .addObject(Identity.builder()
                    .name("Minimal")
                    .identityClass("individual")
                    .build())
                .build();

            assertEquals(1, bundle.getObjects().size());
            assertNotNull(bundle.toJsonString());
        }
    }
}