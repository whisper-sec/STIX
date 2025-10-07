package security.whisper.javastix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.objects.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.common.StixInstant;

/**
 * Simple compilation test to verify the STIX implementation works
 */
@DisplayName("STIX 2.1 Basic Compilation Tests")
public class SimpleCompilationTest {

    @Test
    @DisplayName("Create basic Indicator object")
    void testCreateIndicator() {
        Indicator indicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .build();

        assertNotNull(indicator);
        assertEquals("indicator", indicator.getType());
        assertNotNull(indicator.getId());
        assertTrue(indicator.getId().startsWith("indicator--"));
    }

    @Test
    @DisplayName("Create basic Malware object")
    void testCreateMalware() {
        Malware malware = Malware.builder()
            .name("TestMalware")
            .addLabel("trojan")
            .build();

        assertNotNull(malware);
        assertEquals("malware", malware.getType());
        assertEquals("TestMalware", malware.getName());
        assertTrue(malware.getLabels().contains("trojan"));
    }

    @Test
    @DisplayName("Create basic ThreatActor object")
    void testCreateThreatActor() {
        ThreatActor threatActor = ThreatActor.builder()
            .name("Test Actor")
            .addLabel("hacker")
            .build();

        assertNotNull(threatActor);
        assertEquals("threat-actor", threatActor.getType());
        assertEquals("Test Actor", threatActor.getName());
        assertTrue(threatActor.getLabels().contains("hacker"));
    }

    @Test
    @DisplayName("Create basic Relationship")
    void testCreateRelationship() {
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

        assertNotNull(relationship);
        assertEquals("relationship", relationship.getType());
        assertEquals("uses", relationship.getRelationshipType());
    }

    @Test
    @DisplayName("Create basic Bundle")
    void testCreateBundle() {
        Indicator indicator = Indicator.builder()
            .pattern("[file:hashes.MD5 = 'abc123']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .build();

        Bundle bundle = Bundle.builder()
            .addObject(indicator)
            .build();

        assertNotNull(bundle);
        assertEquals("bundle", bundle.getType());
        assertEquals(1, bundle.getObjects().size());
    }

    @Test
    @DisplayName("Create Attack Pattern")
    void testCreateAttackPattern() {
        AttackPattern attackPattern = AttackPattern.builder()
            .name("Spear Phishing")
            .build();

        assertNotNull(attackPattern);
        assertEquals("attack-pattern", attackPattern.getType());
        assertEquals("Spear Phishing", attackPattern.getName());
    }

    @Test
    @DisplayName("Create Campaign")
    void testCreateCampaign() {
        Campaign campaign = Campaign.builder()
            .name("Operation Test")
            .build();

        assertNotNull(campaign);
        assertEquals("campaign", campaign.getType());
        assertEquals("Operation Test", campaign.getName());
    }

    @Test
    @DisplayName("Create Identity")
    void testCreateIdentity() {
        Identity identity = Identity.builder()
            .name("ACME Corp")
            .identityClass("organization")
            .build();

        assertNotNull(identity);
        assertEquals("identity", identity.getType());
        assertEquals("ACME Corp", identity.getName());
    }

    @Test
    @DisplayName("Create Course of Action")
    void testCreateCourseOfAction() {
        CourseOfAction coa = CourseOfAction.builder()
            .name("Install Antivirus")
            .build();

        assertNotNull(coa);
        assertEquals("course-of-action", coa.getType());
        assertEquals("Install Antivirus", coa.getName());
    }

    @Test
    @DisplayName("Create Vulnerability")
    void testCreateVulnerability() {
        Vulnerability vuln = Vulnerability.builder()
            .name("CVE-2021-0001")
            .build();

        assertNotNull(vuln);
        assertEquals("vulnerability", vuln.getType());
        assertEquals("CVE-2021-0001", vuln.getName());
    }
}