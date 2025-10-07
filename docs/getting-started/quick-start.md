# Quick Start Tutorial

Learn to create, manipulate, and share STIX 2.1 threat intelligence in 5 minutes.

## Your First STIX Object

Let's create an Indicator that represents a malicious IP address:

```java
import security.whisper.javastix.sdo.objects.Indicator;
import security.whisper.javastix.common.StixInstant;

public class QuickStart {
    public static void main(String[] args) {
        Indicator maliciousIP = Indicator.builder()
            .pattern("[ipv4-addr:value = '192.0.2.1']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .name("Known C2 Server")
            .description("Command and control server for APT28")
            .build();

        System.out.println("Created indicator: " + maliciousIP.getId());
    }
}
```

## Creating Multiple Related Objects

Real threat intelligence involves relationships between objects:

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.objects.Relationship;
import security.whisper.javastix.common.StixInstant;

// Create a Threat Actor
ThreatActor aptGroup = ThreatActor.builder()
    .name("APT28")
    .addLabel("nation-state")
    .description("Russian threat actor group")
    .sophistication("advanced")
    .resourceLevel("government")
    .primaryMotivation("ideology")
    .build();

// Create Malware
Malware malware = Malware.builder()
    .name("X-Agent")
    .addLabel("trojan")
    .description("Advanced persistent threat malware")
    .isFamily(true)
    .build();

// Create Attack Pattern
AttackPattern pattern = AttackPattern.builder()
    .name("Spear Phishing")
    .description("Targeted phishing emails with malicious attachments")
    .build();

// Create Relationships
Relationship uses = Relationship.builder()
    .relationshipType("uses")
    .sourceRef(aptGroup)
    .targetRef(malware)
    .description("APT28 uses X-Agent malware")
    .build();

Relationship delivers = Relationship.builder()
    .relationshipType("delivers")
    .sourceRef(pattern)
    .targetRef(malware)
    .description("Spear phishing delivers X-Agent")
    .build();
```

## Building a STIX Bundle

Bundles are containers for sharing STIX objects:

```java
import security.whisper.javastix.bundle.Bundle;

Bundle threatBundle = Bundle.builder()
    .addObject(aptGroup)
    .addObject(malware)
    .addObject(pattern)
    .addObject(uses)
    .addObject(delivers)
    .specVersion("2.1")
    .build();

// Convert to JSON
String json = threatBundle.toJsonString();
System.out.println(json);
```

## Working with Cyber Observables

Document network and system observables:

```java
import security.whisper.javastix.coo.objects.*;
import security.whisper.javastix.sdo.objects.ObservedData;

// Create observable objects
DomainName c2Domain = DomainName.builder()
    .value("evil.example.com")
    .build();

Ipv4Address c2Server = Ipv4Address.builder()
    .value("192.0.2.1")
    .build();

// Create an observation
ObservedData observation = ObservedData.builder()
    .firstObserved(new StixInstant())
    .lastObserved(new StixInstant())
    .numberObserved(42)
    .addObject(c2Domain)
    .addObject(c2Server)
    .build();
```

## Creating an Incident Response Bundle

Document a security incident:

```java
import security.whisper.javastix.sdo.objects.*;
import java.time.Instant;

public class IncidentResponse {
    public Bundle createIncidentBundle() {
        // The victim organization
        Identity victim = Identity.builder()
            .name("Acme Corporation")
            .identityClass("organization")
            .sectors("technology")
            .build();

        // The incident
        Incident incident = Incident.builder()
            .name("Ransomware Attack - October 2025")
            .description("Ransomware deployment via phishing email")
            .build();

        // Indicators found
        Indicator hashIndicator = Indicator.builder()
            .pattern("[file:hashes.SHA256 = 'a1b2c3...']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .description("Ransomware executable hash")
            .build();

        // Course of action taken
        CourseOfAction mitigation = CourseOfAction.builder()
            .name("Isolate and Restore")
            .description("Isolate affected systems and restore from backup")
            .action("1. Disconnect from network\n" +
                    "2. Run antivirus scan\n" +
                    "3. Restore from clean backup")
            .build();

        // Create relationships
        Relationship targets = Relationship.builder()
            .relationshipType("targets")
            .sourceRef(incident)
            .targetRef(victim)
            .build();

        Relationship mitigates = Relationship.builder()
            .relationshipType("mitigates")
            .sourceRef(mitigation)
            .targetRef(incident)
            .build();

        // Build the bundle
        return Bundle.builder()
            .addObject(victim)
            .addObject(incident)
            .addObject(hashIndicator)
            .addObject(mitigation)
            .addObject(targets)
            .addObject(mitigates)
            .build();
    }
}
```

## Working with Threat Intelligence Feeds

Consume external threat data:

```java
import security.whisper.javastix.json.StixParsers;

public class ThreatFeedConsumer {
    public void processThreatFeed(String jsonFeed) {
        // Parse STIX JSON
        Bundle feedBundle = StixParsers.parseBundle(jsonFeed);

        // Process each object
        feedBundle.getObjects().forEach(obj -> {
            if (obj instanceof Indicator) {
                Indicator indicator = (Indicator) obj;
                System.out.println("Found indicator: " + indicator.getPattern());
                // Add to your security tools
            } else if (obj instanceof Malware) {
                Malware malware = (Malware) obj;
                System.out.println("Found malware: " + malware.getName());
                // Update malware database
            }
        });
    }
}
```

## Validating STIX Objects

The library automatically validates objects:

```java
try {
    Indicator invalid = Indicator.builder()
        // Missing required 'pattern' field
        .validFrom(new StixInstant())
        .build();
} catch (ValidationException e) {
    System.err.println("Validation failed: " + e.getMessage());
}
```

## Using STIX Vocabularies

The library enforces STIX vocabulary constraints:

```java
// Valid labels from STIX vocabulary
Indicator indicator = Indicator.builder()
    .pattern("[file:size > 0]")
    .validFrom(new StixInstant())
    .addLabel("malicious-activity")  // Valid
    .addLabel("benign")              // Valid
    // .addLabel("bad-stuff")        // Would throw validation error
    .build();

// Valid threat actor labels
ThreatActor actor = ThreatActor.builder()
    .name("Evil Corp")
    .addLabel("criminal")        // Valid
    .addLabel("nation-state")    // Valid
    // .addLabel("superhacker")   // Would throw validation error
    .build();
```

## Next Steps

### Explore More Examples
- [Threat Intelligence Sharing](../examples/threat-intel-sharing.md)
- [IOC Management](../examples/ioc-management.md)
- [Complete Code Samples](../examples/code-samples/)

### Deep Dive into Concepts
- [Basic STIX Concepts](basic-concepts.md)
- [STIX Objects Guide](../user-guide/stix-objects-guide.md)
- [Vocabulary Reference](../user-guide/vocabulary-reference.md)

### Integration Guides
- [SIEM Integration](../security-use-cases/siem-integration.md)
- [Threat Hunting](../security-use-cases/threat-hunting.md)
- [TAXII Sharing](../security-use-cases/sharing-protocols.md)

## Common Patterns

### Pattern: Indicator with Kill Chain
```java
Indicator.builder()
    .pattern("[network-traffic:dst_port = 4444]")
    .validFrom(new StixInstant())
    .addLabel("malicious-activity")
    .addKillChainPhase(KillChainPhase.builder()
        .killChainName("lockheed-martin-cyber-kill-chain")
        .phaseName("command-and-control")
        .build())
    .build();
```

### Pattern: Campaign Attribution
```java
Campaign campaign = Campaign.builder()
    .name("Operation Shadow")
    .firstSeen(new StixInstant())
    .objective("Data theft")
    .build();

Relationship attribution = Relationship.builder()
    .relationshipType("attributed-to")
    .sourceRef(campaign)
    .targetRef(threatActor)
    .confidence(85)
    .build();
```

### Pattern: Vulnerability Documentation
```java
Vulnerability vuln = Vulnerability.builder()
    .name("CVE-2025-0001")
    .description("Buffer overflow in Example Software")
    .addExternalReference(ExternalReference.builder()
        .sourceName("NVD")
        .url("https://nvd.nist.gov/vuln/detail/CVE-2025-0001")
        .build())
    .build();
```

---

*Congratulations! You've learned the basics of the STIX 2.1 Java Library. [Continue to Basic Concepts →](basic-concepts.md)*