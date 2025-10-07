package security.whisper.javastix.relationships;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.coo.objects.*;
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.json.StixParsers;
import security.whisper.javastix.sro.objects.Relationship;
import security.whisper.javastix.sro.objects.RelationshipSro;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for verifying STIX 2.1 compliance of COO relationships.
 *
 * According to STIX 2.1, relationships can be created between:
 * - SDO to SDO (traditional)
 * - SDO to SCO
 * - SCO to SCO
 */
public class CooRelationshipTest {

    @Test
    @DisplayName("Test SCO to SDO relationship - File related to Malware")
    public void testScoToSdoRelationship() {
        // Create a file COO
        File file = File.builder()
            .name("malware.exe")
            .putHashes("MD5", "abc123def456")
            .size(1024L)
            .build();

        // Create a malware SDO
        Malware malware = Malware.builder()
            .name("TrojanRAT")
            .addLabel("trojan")
            .addLabel("remote-access-trojan")
            .build();

        // Create relationship from COO to SDO
        RelationshipSro relationship = Relationship.builder()
            .relationshipType("related-to")
            .sourceRef(file)
            .targetRef(malware)
            .description("File contains the TrojanRAT malware")
            .build();

        assertNotNull(relationship);
        assertEquals("related-to", relationship.getRelationshipType());
        assertEquals(file.getId(), relationship.getSourceRef().getId());
        assertEquals(malware.getId(), relationship.getTargetRef().getId());

        // Test serialization
        String json = relationship.toJsonString();
        assertNotNull(json);
        assertTrue(json.contains("\"source_ref\":\"" + file.getId() + "\""));
        assertTrue(json.contains("\"target_ref\":\"" + malware.getId() + "\""));
    }

    @Test
    @DisplayName("Test SCO to SCO relationship - Network traffic from IP")
    public void testScoToScoRelationship() {
        // Create IPv4 addresses
        Ipv4Address srcIp = Ipv4Address.builder()
            .value("192.168.1.100")
            .build();

        Ipv4Address dstIp = Ipv4Address.builder()
            .value("10.0.0.1")
            .build();

        // Create network traffic
        NetworkTraffic traffic = NetworkTraffic.builder()
            .srcRef(srcIp)
            .dstRef(dstIp)
            .addProtocol("tcp")
            .srcPort(45678)
            .dstPort(443)
            .build();

        // Create relationship from network traffic to IP
        RelationshipSro relationship = Relationship.builder()
            .relationshipType("originates-from")
            .sourceRef(traffic)
            .targetRef(srcIp)
            .description("Network traffic originates from this IP")
            .build();

        assertNotNull(relationship);
        assertEquals("originates-from", relationship.getRelationshipType());
        assertEquals(traffic.getId(), relationship.getSourceRef().getId());
        assertEquals(srcIp.getId(), relationship.getTargetRef().getId());
    }

    @Test
    @DisplayName("Test COO belongs-to Identity relationship")
    public void testCooBelongsToIdentity() {
        // Create an identity
        Identity identity = Identity.builder()
            .name("ACME Corporation")
            .identityClass("organization")
            .build();

        // Create a file that belongs to the identity
        File file = File.builder()
            .name("company-data.xlsx")
            .size(2048L)
            .build();

        // Create belongs-to relationship
        RelationshipSro relationship = Relationship.builder()
            .relationshipType("belongs-to")
            .sourceRef(file)
            .targetRef(identity)
            .build();

        assertNotNull(relationship);
        assertEquals("belongs-to", relationship.getRelationshipType());
        assertEquals(file.getId(), relationship.getSourceRef().getId());
        assertEquals(identity.getId(), relationship.getTargetRef().getId());
    }

    @Test
    @DisplayName("Test Bundle with mixed SDO and SCO relationships")
    public void testBundleWithMixedRelationships() throws Exception {
        // Create objects
        File file = File.builder()
            .name("payload.bin")
            .size(4096L)
            .build();

        Malware malware = Malware.builder()
            .name("Dropper")
            .addLabel("dropper")
            .build();

        Ipv4Address ip = Ipv4Address.builder()
            .value("192.168.1.1")
            .build();

        // Create relationships
        RelationshipSro fileToMalware = Relationship.builder()
            .relationshipType("related-to")
            .sourceRef(file)
            .targetRef(malware)
            .build();

        RelationshipSro fileToFile = Relationship.builder()
            .relationshipType("contains")
            .sourceRef(file)
            .targetRef(file)  // Self-reference for testing
            .build();

        // Create bundle
        Bundle bundle = Bundle.builder()
            .addObject(file)
            .addObject(malware)
            .addObject(ip)
            .addObject(fileToMalware)
            .addObject(fileToFile)
            .build();

        assertEquals(5, bundle.getObjects().size());

        // Serialize and deserialize
        String json = bundle.toJsonString();
        assertNotNull(json);

        // Parse back
        Bundle parsedBundle = StixParsers.parseBundle(json);
        assertNotNull(parsedBundle);
        assertEquals(5, parsedBundle.getObjects().size());
    }

    @Test
    @DisplayName("Test dehydrated COO reference in relationship")
    public void testDehydratedCooReference() throws Exception {
        // Create JSON with dehydrated COO reference
        String json = "{\n" +
            "  \"type\": \"relationship\",\n" +
            "  \"spec_version\": \"2.1\",\n" +
            "  \"id\": \"relationship--" + java.util.UUID.randomUUID() + "\",\n" +
            "  \"created\": \"2025-01-15T10:00:00.000Z\",\n" +
            "  \"modified\": \"2025-01-15T10:00:00.000Z\",\n" +
            "  \"relationship_type\": \"related-to\",\n" +
            "  \"source_ref\": \"file--12345678-1234-1234-1234-123456789012\",\n" +
            "  \"target_ref\": \"malware--87654321-4321-4321-4321-210987654321\"\n" +
            "}";

        // Parse the relationship
        RelationshipSro relationship = (RelationshipSro) StixParsers.parse(json, RelationshipSro.class);

        assertNotNull(relationship);
        assertEquals("related-to", relationship.getRelationshipType());
        assertEquals("file--12345678-1234-1234-1234-123456789012", relationship.getSourceRef().getId());
        assertEquals("malware--87654321-4321-4321-4321-210987654321", relationship.getTargetRef().getId());

        // Verify types
        assertEquals("file", relationship.getSourceRef().getType());
        assertEquals("malware", relationship.getTargetRef().getType());
    }
}