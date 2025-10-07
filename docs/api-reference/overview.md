# API Reference Overview

The STIX 2.1 Java Library provides a comprehensive API for creating, parsing, and managing STIX objects. This reference guide covers the main packages and classes.

## Core Packages

### `security.whisper.javastix.bundle`
Core bundle functionality for grouping STIX objects.

- **`Bundle`** - Container for STIX objects
- **`BundleableObject`** - Interface for objects that can be bundled

### `security.whisper.javastix.sdo.objects`
STIX Domain Objects (SDO) representing cyber threat intelligence entities.

- **`AttackPattern`** - Methods adversaries use to compromise targets
- **`Campaign`** - Grouping of adversarial behaviors over time
- **`CourseOfAction`** - Actions to prevent or respond to attacks
- **`Grouping`** - Explicit collection of STIX objects
- **`Identity`** - Individuals, organizations, or groups
- **`Incident`** - Security incidents and breaches
- **`Indicator`** - Patterns for detecting suspicious activity
- **`Infrastructure`** - Physical or virtual resources
- **`IntrusionSet`** - Grouped malicious activities
- **`Location`** - Geographic location or region
- **`Malware`** - Malicious software instances
- **`MalwareAnalysis`** - Results of malware analysis
- **`Note`** - Additional context notes
- **`ObservedData`** - Raw cyber observables
- **`Opinion`** - Assessment of STIX content
- **`Report`** - Collections of threat intelligence
- **`ThreatActor`** - Malicious actors
- **`Tool`** - Software used by threat actors
- **`Vulnerability`** - Software vulnerabilities

### `security.whisper.javastix.sro.objects`
STIX Relationship Objects (SRO) representing connections between SDOs.

- **`Relationship`** - Directed relationship between objects
- **`Sighting`** - Observation of STIX content

### `security.whisper.javastix.coo.objects`
Cyber Observable Objects (SCO) representing technical observables.

- **`Artifact`** - Raw artifact data
- **`AutonomousSystem`** - AS number
- **`Directory`** - File system directory
- **`DomainName`** - Domain name
- **`EmailAddress`** - Email address
- **`EmailMessage`** - Email message
- **`File`** - File with metadata
- **`IPv4Address`** - IPv4 address
- **`IPv6Address`** - IPv6 address
- **`MACAddress`** - MAC address
- **`Mutex`** - Mutual exclusion object
- **`NetworkTraffic`** - Network connection
- **`Process`** - System process
- **`Software`** - Software application
- **`URL`** - Uniform Resource Locator
- **`UserAccount`** - User account
- **`WindowsRegistryKey`** - Windows registry key
- **`X509Certificate`** - X.509 certificate

### `security.whisper.javastix.common`
Common utilities and types.

- **`StixInstant`** - Timestamp handling
- **`StixId`** - STIX identifier generation
- **`StixSpecVersion`** - STIX specification version

### `security.whisper.javastix.validation`
Validation framework for STIX compliance.

- **`StixValidator`** - Main validation entry point
- **`ValidationException`** - Validation errors

### `security.whisper.javastix.json`
JSON serialization and deserialization.

- **`StixParsers`** - Parse JSON to STIX objects
- **`ObjectMapperConfigurer`** - Jackson configuration

## Quick API Examples

### Creating Objects

```java
// Create a threat actor
ThreatActor actor = ThreatActor.builder()
    .name("APT29")
    .addLabel("nation-state")
    .sophistication("advanced")
    .resourceLevel("government")
    .primaryMotivation("espionage")
    .build();

// Create an indicator
Indicator indicator = Indicator.builder()
    .pattern("[file:hashes.MD5 = 'abc123']")
    .validFrom(new StixInstant())
    .addLabel("malicious-activity")
    .confidence(95)
    .build();

// Create a relationship
Relationship rel = Relationship.builder()
    .relationshipType("indicates")
    .sourceRef(indicator)
    .targetRef(actor)
    .build();

// Bundle objects
Bundle bundle = Bundle.builder()
    .addObject(actor)
    .addObject(indicator)
    .addObject(rel)
    .build();
```

### Parsing JSON

```java
// Parse a bundle from JSON
String json = "{ \"type\": \"bundle\", ... }";
Bundle bundle = StixParsers.parseBundle(json);

// Parse a specific object type
Indicator indicator = StixParsers.parseIndicator(json);

// Access parsed objects
for (BundleableObject obj : bundle.getObjects()) {
    if (obj instanceof ThreatActor) {
        ThreatActor actor = (ThreatActor) obj;
        System.out.println(actor.getName());
    }
}
```

### Working with Timestamps

```java
// Current timestamp
StixInstant now = new StixInstant();

// From string
StixInstant timestamp = StixInstant.fromString("2025-01-15T10:00:00.000Z");

// Add duration
StixInstant future = now.plusDays(30);
StixInstant past = now.minusHours(24);

// Compare timestamps
if (timestamp.isBefore(now)) {
    // Handle past timestamp
}
```

### Validation

```java
// Validate an object
try {
    StixValidator validator = new StixValidator();
    validator.validate(indicator);
} catch (ValidationException e) {
    // Handle validation errors
    System.err.println("Validation failed: " + e.getMessage());
}

// Validate a bundle
Bundle bundle = Bundle.builder()
    .addObject(indicator)
    .build();

if (bundle.isValid()) {
    // Bundle is valid
}
```

### Custom Properties

```java
// Add custom properties to any STIX object
Malware malware = Malware.builder()
    .name("CustomRAT")
    .addLabel("remote-access-trojan")
    .customProperty("x_internal_id", "MAL-2025-001")
    .customProperty("x_severity", "critical")
    .customProperty("x_confidence_score", 87.5)
    .build();

// Access custom properties
Map<String, Object> customProps = malware.getCustomProperties();
String internalId = (String) customProps.get("x_internal_id");
```

### Pattern Creation

```java
// Simple pattern
String simple = "[file:name = 'malware.exe']";

// Complex pattern with multiple observables
String complex = "[file:hashes.MD5 = 'abc123' AND " +
                "file:size > 1000] FOLLOWEDBY " +
                "[network-traffic:dst_port = 443]";

// Pattern with temporal constraints
String temporal = "[file:created = '2025-01-15T10:00:00Z'] " +
                 "START t'2025-01-15T00:00:00Z' " +
                 "STOP t'2025-01-16T00:00:00Z'";

Indicator patternIndicator = Indicator.builder()
    .pattern(complex)
    .validFrom(new StixInstant())
    .build();
```

### External References

```java
// MITRE ATT&CK reference
ExternalReference mitre = ExternalReference.builder()
    .sourceName("MITRE ATT&CK")
    .externalId("T1566.001")
    .url("https://attack.mitre.org/techniques/T1566/001/")
    .description("Spearphishing Attachment")
    .build();

// CVE reference
ExternalReference cve = ExternalReference.builder()
    .sourceName("NVD")
    .externalId("CVE-2021-44228")
    .url("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
    .description("Log4Shell vulnerability")
    .build();

// Add to objects
Vulnerability vuln = Vulnerability.builder()
    .name("Log4Shell")
    .addExternalReference(cve)
    .build();
```

### Kill Chain Phases

```java
// MITRE ATT&CK kill chain
KillChainPhase attackPhase = KillChainPhase.builder()
    .killChainName("mitre-attack")
    .phaseName("initial-access")
    .build();

// Lockheed Martin kill chain
KillChainPhase lmPhase = KillChainPhase.builder()
    .killChainName("lockheed-martin-cyber-kill-chain")
    .phaseName("delivery")
    .build();

// Add to attack pattern
AttackPattern pattern = AttackPattern.builder()
    .name("Phishing")
    .addKillChainPhase(attackPhase)
    .addKillChainPhase(lmPhase)
    .build();
```

## Builder Pattern

All STIX objects use the builder pattern for construction:

```java
ThreatActor.builder()
    .name("...")           // Required fields
    .addLabel("...")       // Required fields
    .description("...")    // Optional fields
    .sophistication("...") // Optional fields
    .build();              // Create immutable object
```

### Builder Methods

- **`.name(String)`** - Set object name
- **`.description(String)`** - Set description
- **`.addLabel(String)`** - Add a single label
- **`.addAllLabels(Collection)`** - Add multiple labels
- **`.confidence(Integer)`** - Set confidence level (0-100)
- **`.customProperty(String, Object)`** - Add custom property
- **`.addExternalReference(ExternalReference)`** - Add reference
- **`.created(StixInstant)`** - Override creation timestamp
- **`.modified(StixInstant)`** - Override modification timestamp
- **`.createdBy(Identity)`** - Set creator identity
- **`.build()`** - Create the immutable object

## Immutability

All STIX objects are immutable after creation:

```java
// Objects are immutable
ThreatActor actor = ThreatActor.builder()
    .name("APT1")
    .addLabel("nation-state")
    .build();

// Cannot modify after creation
// actor.setName("APT2"); // This method doesn't exist

// Create modified copy
ThreatActor updatedActor = actor.withName("APT2");
```

## Thread Safety

All STIX objects are thread-safe due to immutability:

```java
// Safe to share between threads
final Bundle bundle = createBundle();

// Thread 1
executor.submit(() -> {
    processBundle(bundle);
});

// Thread 2
executor.submit(() -> {
    analyzeBundle(bundle);
});
```

## Serialization

### To JSON

```java
// Serialize single object
Indicator indicator = createIndicator();
String json = indicator.toJsonString();

// Pretty print
String prettyJson = indicator.toJsonString(true);

// Serialize bundle
Bundle bundle = createBundle();
String bundleJson = bundle.toJsonString();

// Using ObjectMapper directly
ObjectMapper mapper = ObjectMapperConfigurer.buildObjectMapper();
mapper.writeValueAsString(indicator);
```

### From JSON

```java
// Parse with type detection
String json = "{ \"type\": \"indicator\", ... }";
BundleableObject obj = StixParsers.parse(json);

// Parse specific type
Indicator indicator = StixParsers.parseIndicator(json);

// Parse bundle
Bundle bundle = StixParsers.parseBundle(json);

// Using ObjectMapper directly
ObjectMapper mapper = ObjectMapperConfigurer.buildObjectMapper();
Indicator ind = mapper.readValue(json, Indicator.class);
```

## Error Handling

```java
try {
    // Parse potentially invalid JSON
    Bundle bundle = StixParsers.parseBundle(untrustedJson);

    // Validate the bundle
    StixValidator validator = new StixValidator();
    validator.validate(bundle);

} catch (JsonProcessingException e) {
    // Handle JSON parsing errors
    log.error("Invalid JSON", e);

} catch (ValidationException e) {
    // Handle STIX validation errors
    log.error("Invalid STIX: " + e.getMessage());

} catch (Exception e) {
    // Handle other errors
    log.error("Unexpected error", e);
}
```

## Best Practices

1. **Always validate external data** before processing
2. **Use builders** for object creation
3. **Handle exceptions** appropriately
4. **Leverage immutability** for thread safety
5. **Use type checking** when processing mixed objects
6. **Set appropriate confidence levels** on indicators
7. **Include external references** for context
8. **Use custom properties** sparingly and with `x_` prefix
9. **Set valid time windows** for indicators
10. **Group related objects** in bundles

## Next Steps

- See [Developer Guide](../user-guide/for-developers.md) for detailed development instructions
- See [Examples](../examples/) for complete code samples
- See [Integration Patterns](../examples/integration-patterns.md) for system integration