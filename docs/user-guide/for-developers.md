# Developer Guide

A comprehensive guide for software developers working with the STIX 2.1 Java Library.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Builder Pattern](#builder-pattern)
3. [Immutable Objects](#immutable-objects)
4. [Validation Framework](#validation-framework)
5. [Serialization & Deserialization](#serialization--deserialization)
6. [Error Handling](#error-handling)
7. [Performance Considerations](#performance-considerations)
8. [Best Practices](#best-practices)

## Architecture Overview

The library is built on several key architectural principles:

- **Immutability**: All STIX objects are immutable after creation
- **Builder Pattern**: Fluent builders for object construction
- **Type Safety**: Strong typing with generics where appropriate
- **Validation**: Automatic validation against STIX 2.1 specification
- **Extensibility**: Support for custom properties and extensions

### Package Structure

```
security.whisper.javastix
├── bundle/          # Bundle creation and management
├── common/          # Common properties and utilities
├── coo/            # Cyber Observable Objects
│   └── objects/    # Specific observable types
├── sdo/            # STIX Domain Objects
│   └── objects/    # Specific SDO types
├── sro/            # STIX Relationship Objects
│   └── objects/    # Relationship and Sighting
├── validation/     # Validation framework
├── vocabulary/     # STIX vocabularies
└── json/           # Serialization utilities
```

## Builder Pattern

Every STIX object uses a fluent builder pattern for construction:

### Basic Builder Usage

```java
Indicator indicator = Indicator.builder()
    .pattern("[file:hashes.MD5 = 'abc123']")
    .validFrom(new StixInstant())
    .validUntil(new StixInstant().plusDays(30))
    .name("Malware File Hash")
    .description("Known malware hash from campaign X")
    .confidence(95)
    .addLabel("malicious-activity")
    .build();
```

### Nested Object Building

```java
Report report = Report.builder()
    .name("Q4 2025 Threat Report")
    .published(new StixInstant())
    .addLabel("threat-report")
    .addObjectRef(
        Indicator.builder()
            .pattern("[ipv4-addr:value = '10.0.0.1']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .build()
    )
    .addObjectRef(
        ThreatActor.builder()
            .name("APT99")
            .addLabel("nation-state")
            .build()
    )
    .build();
```

### Conditional Building

```java
Indicator.Builder builder = Indicator.builder()
    .pattern(pattern)
    .validFrom(new StixInstant())
    .addLabel("malicious-activity");

if (hasConfidenceScore) {
    builder.confidence(confidenceValue);
}

if (hasKillChain) {
    builder.addKillChainPhase(killChainPhase);
}

Indicator indicator = builder.build();
```

## Immutable Objects

All STIX objects are immutable once created, following the Immutables library pattern:

### Why Immutability?

- **Thread Safety**: Objects can be shared across threads without synchronization
- **Cache Friendly**: Objects can be cached without defensive copying
- **Predictable**: Objects cannot change after creation
- **Hashable**: Safe to use as Map keys or in Sets

### Working with Immutable Objects

```java
// Objects are immutable - this is safe
Malware malware = Malware.builder()
    .name("Zeus")
    .addLabel("trojan")
    .build();

// Share across threads - no synchronization needed
CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() ->
    processInThread1(malware)
);

CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() ->
    processInThread2(malware)
);
```

### Creating Modified Copies

Since objects are immutable, use builders to create modified versions:

```java
Indicator original = Indicator.builder()
    .pattern("[file:size > 1000]")
    .validFrom(new StixInstant())
    .addLabel("suspicious")
    .build();

// Create a modified copy with updated confidence
Indicator updated = Indicator.builder()
    .from(original)  // Copy all properties
    .confidence(85)   // Add/override confidence
    .build();
```

## Validation Framework

The library uses Hibernate Validator for automatic validation:

### Automatic Validation

```java
try {
    // This will throw ValidationException - missing required pattern
    Indicator invalid = Indicator.builder()
        .validFrom(new StixInstant())
        .build();
} catch (ValidationException e) {
    e.getConstraintViolations().forEach(violation ->
        System.err.println(violation.getPropertyPath() + ": " + violation.getMessage())
    );
}
```

### Custom Validation

```java
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import javax.validation.Validation;

ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
Validator validator = factory.getValidator();

Indicator indicator = Indicator.builder()
    .pattern("[file:size > 0]")
    .validFrom(new StixInstant())
    .addLabel("malicious-activity")
    .build();

Set<ConstraintViolation<Indicator>> violations = validator.validate(indicator);
if (!violations.isEmpty()) {
    // Handle validation errors
}
```

### Vocabulary Validation

STIX vocabularies are automatically validated:

```java
// Valid - uses allowed vocabulary term
ThreatActor valid = ThreatActor.builder()
    .name("APT1")
    .addLabel("nation-state")  // Valid term
    .build();

// Invalid - throws ValidationException
ThreatActor invalid = ThreatActor.builder()
    .name("APT1")
    .addLabel("super-hacker")  // Not in vocabulary!
    .build();
```

## Serialization & Deserialization

### Object to JSON

```java
// Single object
Malware malware = Malware.builder()
    .name("WannaCry")
    .addLabel("ransomware")
    .build();

String json = malware.toJsonString();

// Bundle of objects
Bundle bundle = Bundle.builder()
    .addObject(malware)
    .addObject(indicator)
    .build();

String bundleJson = bundle.toJsonString();

// Pretty printing
ObjectMapper mapper = StixParsers.getJsonMapper();
mapper.enable(SerializationFeature.INDENT_OUTPUT);
String prettyJson = mapper.writeValueAsString(bundle);
```

### JSON to Object

```java
// Parse single object
String indicatorJson = "{\"type\":\"indicator\",\"pattern\":\"[file:size > 0]\"}";
Indicator parsed = StixParsers.parse(indicatorJson, Indicator.class);

// Parse bundle
String bundleJson = "{\"type\":\"bundle\",\"objects\":[...]}";
Bundle parsedBundle = StixParsers.parseBundle(bundleJson);

// Parse with error handling
try {
    Bundle bundle = StixParsers.parseBundle(untrustedJson);
    processBundle(bundle);
} catch (JsonProcessingException e) {
    log.error("Invalid STIX JSON", e);
}
```

### Custom Serialization

```java
// Configure custom ObjectMapper
ObjectMapper mapper = new ObjectMapper();
mapper.registerModule(new JavaTimeModule());
mapper.registerModule(new StixModule());
mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

// Use custom mapper
String json = mapper.writeValueAsString(stixObject);
```

## Error Handling

### Validation Errors

```java
public Indicator createIndicator(String pattern, String label) {
    try {
        return Indicator.builder()
            .pattern(pattern)
            .validFrom(new StixInstant())
            .addLabel(label)
            .build();
    } catch (ValidationException e) {
        // Log validation errors
        e.getConstraintViolations().forEach(v ->
            log.error("Validation failed for {}: {}",
                v.getPropertyPath(), v.getMessage())
        );
        throw new IllegalArgumentException("Invalid indicator data", e);
    }
}
```

### Parsing Errors

```java
public Bundle parseThrea

tFeed(String json) {
    try {
        return StixParsers.parseBundle(json);
    } catch (JsonParseException e) {
        log.error("Malformed JSON", e);
        return Bundle.builder().build();  // Return empty bundle
    } catch (JsonMappingException e) {
        log.error("Invalid STIX structure", e);
        return Bundle.builder().build();
    } catch (IOException e) {
        log.error("IO error parsing JSON", e);
        throw new RuntimeException("Failed to parse threat feed", e);
    }
}
```

### Null Safety

```java
// Use Optional for nullable fields
Optional<String> description = indicator.getDescription();
description.ifPresent(desc ->
    log.info("Indicator description: {}", desc)
);

// Safe collection access
Set<String> labels = indicator.getLabels();
if (labels != null && !labels.isEmpty()) {
    processLabels(labels);
}

// Builder null handling
Indicator.Builder builder = Indicator.builder()
    .pattern(pattern)
    .validFrom(new StixInstant());

if (name != null) {
    builder.name(name);  // Only set if not null
}
```

## Performance Considerations

### Object Creation

```java
// Reuse builders for similar objects
Indicator.Builder template = Indicator.builder()
    .validFrom(new StixInstant())
    .addLabel("malicious-activity");

List<Indicator> indicators = ipAddresses.stream()
    .map(ip -> template
        .pattern("[ipv4-addr:value = '" + ip + "']")
        .build())
    .collect(Collectors.toList());
```

### Bundle Size

```java
// Process large bundles in chunks
public void processLargeBundle(List<BundleableObject> objects) {
    int chunkSize = 1000;
    for (int i = 0; i < objects.size(); i += chunkSize) {
        List<BundleableObject> chunk = objects.subList(i,
            Math.min(i + chunkSize, objects.size()));

        Bundle bundle = Bundle.builder()
            .addAllObjects(chunk)
            .build();

        sendBundle(bundle);
    }
}
```

### Memory Management

```java
// Stream processing for large datasets
public void processThreatFeed(Path feedFile) throws IOException {
    try (Stream<String> lines = Files.lines(feedFile)) {
        lines.map(this::parseIndicator)
             .filter(Objects::nonNull)
             .forEach(this::processIndicator);
    }
}

// Clear references for GC
Bundle bundle = createLargeBundle();
String json = bundle.toJsonString();
bundle = null;  // Allow GC of bundle while processing JSON
sendJson(json);
```

## Best Practices

### 1. Use Type-Safe Methods

```java
// Good - Type safe
Relationship rel = Relationship.builder()
    .sourceRef(threatActor)  // Takes StixDomainObject
    .targetRef(malware)      // Takes StixDomainObject
    .relationshipType("uses")
    .build();

// Avoid - String based
Relationship rel = Relationship.builder()
    .sourceRef("threat-actor--123")  // Error prone
    .targetRef("malware--456")
    .relationshipType("uses")
    .build();
```

### 2. Validate Early

```java
public class IndicatorService {
    private final Validator validator;

    public void addIndicator(String pattern, String label) {
        // Validate inputs early
        Objects.requireNonNull(pattern, "Pattern cannot be null");
        Objects.requireNonNull(label, "Label cannot be null");

        if (!isValidPattern(pattern)) {
            throw new IllegalArgumentException("Invalid pattern syntax");
        }

        Indicator indicator = Indicator.builder()
            .pattern(pattern)
            .validFrom(new StixInstant())
            .addLabel(label)
            .build();

        // Additional validation if needed
        Set<ConstraintViolation<Indicator>> violations =
            validator.validate(indicator);
        if (!violations.isEmpty()) {
            throw new ValidationException(violations);
        }

        saveIndicator(indicator);
    }
}
```

### 3. Use Constants for Vocabularies

```java
public class StixConstants {
    // Relationship types
    public static final String USES = "uses";
    public static final String INDICATES = "indicates";
    public static final String MITIGATES = "mitigates";

    // Labels
    public static final String MALICIOUS_ACTIVITY = "malicious-activity";
    public static final String BENIGN = "benign";

    // Identity classes
    public static final String INDIVIDUAL = "individual";
    public static final String ORGANIZATION = "organization";
}

// Usage
Indicator indicator = Indicator.builder()
    .pattern(pattern)
    .validFrom(new StixInstant())
    .addLabel(StixConstants.MALICIOUS_ACTIVITY)
    .build();
```

### 4. Document Custom Properties

```java
/**
 * Creates an indicator with custom properties for internal tracking.
 *
 * Custom properties:
 * - x_internal_id: Internal tracking ID
 * - x_confidence_source: Source of confidence score
 * - x_last_validated: Last validation timestamp
 */
public Indicator createCustomIndicator(String pattern) {
    return Indicator.builder()
        .pattern(pattern)
        .validFrom(new StixInstant())
        .addLabel("malicious-activity")
        .customProperty("x_internal_id", generateId())
        .customProperty("x_confidence_source", "automated_analysis")
        .customProperty("x_last_validated", Instant.now().toString())
        .build();
}
```

### 5. Handle Circular References

```java
// Avoid circular references in relationships
public Bundle createHierarchy() {
    ThreatActor parent = ThreatActor.builder()
        .name("Parent Group")
        .addLabel("criminal")
        .build();

    ThreatActor child = ThreatActor.builder()
        .name("Child Group")
        .addLabel("criminal")
        .build();

    // One-way relationship to avoid circles
    Relationship rel = Relationship.builder()
        .relationshipType("attributed-to")
        .sourceRef(child)
        .targetRef(parent)
        .build();

    return Bundle.builder()
        .addObject(parent)
        .addObject(child)
        .addObject(rel)
        .build();
}
```

## Integration Patterns

### Repository Pattern

```java
public interface StixRepository {
    void save(BundleableObject object);
    Optional<BundleableObject> findById(String id);
    List<Indicator> findIndicatorsByLabel(String label);
    List<BundleableObject> findByType(String type);
}

@Repository
public class MongoStixRepository implements StixRepository {
    private final MongoTemplate mongoTemplate;

    public void save(BundleableObject object) {
        String json = object.toJsonString();
        Document doc = Document.parse(json);
        mongoTemplate.save(doc, "stix_objects");
    }

    public Optional<BundleableObject> findById(String id) {
        Query query = new Query(Criteria.where("id").is(id));
        Document doc = mongoTemplate.findOne(query, Document.class, "stix_objects");
        return Optional.ofNullable(doc)
            .map(Document::toJson)
            .map(json -> StixParsers.parseObject(json));
    }
}
```

### Service Layer

```java
@Service
public class ThreatIntelligenceService {
    private final StixRepository repository;
    private final KafkaTemplate<String, String> kafkaTemplate;

    @Transactional
    public void processThreatIndicator(Indicator indicator) {
        // Validate
        validateIndicator(indicator);

        // Enrich
        Indicator enriched = enrichIndicator(indicator);

        // Store
        repository.save(enriched);

        // Share
        Bundle bundle = Bundle.builder()
            .addObject(enriched)
            .build();

        kafkaTemplate.send("threat-intel", bundle.toJsonString());
    }
}
```

## Next Steps

- Explore [API Reference](../api-reference/) for detailed class documentation
- See [Code Examples](../examples/code-samples/) for complete applications
- Read [Security Use Cases](../security-use-cases/) for integration patterns
- Check [Troubleshooting Guide](../reference/troubleshooting.md) for common issues

---

*[Back to Documentation Index](../README.md)*