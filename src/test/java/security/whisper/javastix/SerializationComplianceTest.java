package security.whisper.javastix;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.objects.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.json.StixParsers;

/**
 * Tests to ensure STIX objects serialize in compliance with STIX 2.1 specification
 * Specifically checks that custom types (timestamps, booleans, etc.) serialize as primitive values
 * and not as nested objects.
 */
@DisplayName("STIX 2.1 JSON Serialization Compliance Tests")
public class SerializationComplianceTest {

    private final ObjectMapper mapper = StixParsers.getJsonMapper();

    @Test
    @DisplayName("Timestamps should serialize as ISO 8601 strings, not objects")
    void testTimestampSerializationAsString() throws Exception {
        Indicator indicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .build();

        String json = mapper.writeValueAsString(indicator);
        JsonNode node = mapper.readTree(json);

        // Verify 'created' field exists and is a string (not an object)
        assertTrue(node.has("created"), "Indicator should have 'created' field");
        assertTrue(node.get("created").isTextual(),
            "Timestamp 'created' should be a string, not an object. Got: " + node.get("created"));

        // Verify it matches ISO 8601 format
        String createdValue = node.get("created").asText();
        assertTrue(createdValue.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z"),
            "Timestamp should be in ISO 8601 format (YYYY-MM-DDTHH:MM:SS.sssZ). Got: " + createdValue);

        // Verify 'modified' field exists and is a string
        assertTrue(node.has("modified"), "Indicator should have 'modified' field");
        assertTrue(node.get("modified").isTextual(),
            "Timestamp 'modified' should be a string, not an object. Got: " + node.get("modified"));
    }

    @Test
    @DisplayName("Bundle with objects should serialize with objects array")
    void testBundleSerializationWithObjects() throws Exception {
        Indicator indicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'abc123']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .build();

        Malware malware = Malware.builder()
            .name("TestMalware")
            .addLabel("trojan")
            .build();

        Bundle bundle = Bundle.builder()
            .addObject(indicator)
            .addObject(malware)
            .build();

        String json = mapper.writeValueAsString(bundle);
        JsonNode node = mapper.readTree(json);

        // Verify 'objects' field exists and is an array
        assertTrue(node.has("objects"), "Bundle should have 'objects' field");
        assertTrue(node.get("objects").isArray(),
            "Bundle 'objects' should be an array, not missing or object. Got: " + node.get("objects"));
        assertEquals(2, node.get("objects").size(),
            "Bundle should contain 2 objects");
    }

    @Test
    @DisplayName("Confidence field (if present) should serialize as integer")
    void testConfidenceFieldSerialization() throws Exception {
        // Create indicator with confidence
        Indicator indicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .confidence(85)
            .build();

        String json = mapper.writeValueAsString(indicator);
        JsonNode node = mapper.readTree(json);

        // Verify 'confidence' field exists and is a number (not an object)
        assertTrue(node.has("confidence"), "Indicator should have 'confidence' field");
        assertTrue(node.get("confidence").isNumber(),
            "Confidence should be a number, not an object. Got: " + node.get("confidence"));
        assertEquals(85, node.get("confidence").asInt());
    }

    @Test
    @DisplayName("All SDO types should have properly serialized timestamps")
    void testAllSdoTypesTimestamps() throws Exception {
        // Test various SDO types
        AttackPattern attackPattern = AttackPattern.builder()
            .name("Test Pattern")
            .build();

        Campaign campaign = Campaign.builder()
            .name("Test Campaign")
            .build();

        Identity identity = Identity.builder()
            .name("Test Identity")
            .identityClass("individual")
            .build();

        ThreatActor threatActor = ThreatActor.builder()
            .name("Test Actor")
            .addLabel("hacker")
            .build();

        // Check each one
        for (Object obj : new Object[]{attackPattern, campaign, identity, threatActor}) {
            String json = mapper.writeValueAsString(obj);
            JsonNode node = mapper.readTree(json);

            assertTrue(node.get("created").isTextual(),
                obj.getClass().getSimpleName() + " 'created' should be a string. Got: " + node.get("created"));
            assertTrue(node.get("modified").isTextual(),
                obj.getClass().getSimpleName() + " 'modified' should be a string. Got: " + node.get("modified"));
        }
    }

    @Test
    @DisplayName("Relationship timestamps should serialize correctly")
    void testRelationshipTimestamps() throws Exception {
        ThreatActor actor = ThreatActor.builder()
            .name("Test Actor")
            .addLabel("hacker")
            .build();

        Malware malware = Malware.builder()
            .name("TestMalware")
            .addLabel("trojan")
            .build();

        Relationship relationship = Relationship.builder()
            .relationshipType("uses")
            .sourceRef(actor)
            .targetRef(malware)
            .build();

        String json = mapper.writeValueAsString(relationship);
        JsonNode node = mapper.readTree(json);

        assertTrue(node.get("created").isTextual(),
            "Relationship 'created' should be a string. Got: " + node.get("created"));
        assertTrue(node.get("modified").isTextual(),
            "Relationship 'modified' should be a string. Got: " + node.get("modified"));
    }

    @Test
    @DisplayName("Valid_from timestamp in Indicator should serialize as ISO 8601 string")
    void testValidFromSerialization() throws Exception {
        StixInstant validFrom = new StixInstant();
        Indicator indicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
            .validFrom(validFrom)
            .addLabel("malicious-activity")
            .build();

        String json = mapper.writeValueAsString(indicator);
        JsonNode node = mapper.readTree(json);

        // Verify valid_from is a string
        assertTrue(node.has("valid_from"), "Indicator should have 'valid_from' field");
        assertTrue(node.get("valid_from").isTextual(),
            "Timestamp 'valid_from' should be a string, not an object. Got: " + node.get("valid_from"));

        // Verify it matches ISO 8601 format
        String validFromValue = node.get("valid_from").asText();
        assertTrue(validFromValue.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z"),
            "valid_from should be in ISO 8601 format. Got: " + validFromValue);
    }
}
