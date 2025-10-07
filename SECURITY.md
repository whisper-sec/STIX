# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to security@whisper.security.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Disclosure Policy

When we receive a security bug report, we will:

1. **Confirm** the problem and determine the affected versions
2. **Audit** code to find any potential similar problems
3. **Prepare** fixes for all releases still under maintenance
4. **Release** patches as soon as possible

## Security Best Practices for Users

### 1. Keep Dependencies Updated

Regularly update the library to the latest version:

```xml
<dependency>
    <groupId>security.whisper</groupId>
    <artifactId>stix2.1</artifactId>
    <version>1.0.0</version> <!-- Use latest version -->
</dependency>
```

### 2. Input Validation

Always validate external STIX data before processing:

```java
public Bundle processUntrustedSTIX(String untrustedJson) {
    try {
        // Parse and validate
        Bundle bundle = StixParsers.parseBundle(untrustedJson);

        // Additional validation
        validateBundle(bundle);

        // Check for suspicious patterns
        checkForMaliciousPatterns(bundle);

        return bundle;
    } catch (Exception e) {
        log.error("Invalid or malicious STIX data", e);
        throw new SecurityException("Cannot process untrusted STIX data");
    }
}

private void validateBundle(Bundle bundle) {
    // Implement additional security checks
    if (bundle.getObjects().size() > 10000) {
        throw new SecurityException("Bundle too large");
    }

    // Check for recursive references
    // Check for suspicious patterns
    // Validate all object types
}
```

### 3. Secure Serialization

Be careful when serializing/deserializing STIX objects:

```java
// Configure ObjectMapper securely
ObjectMapper mapper = new ObjectMapper();
mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
mapper.enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
mapper.enable(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS);

// Set maximum sizes
mapper.getFactory().setStreamReadConstraints(
    StreamReadConstraints.builder()
        .maxStringLength(1_000_000)  // 1MB max string
        .maxNestingDepth(100)        // Max JSON nesting
        .build()
);
```

### 4. Data Sanitization

Sanitize STIX data before displaying or storing:

```java
public String sanitizeDescription(String description) {
    if (description == null) return null;

    // Remove potential XSS vectors
    description = description.replaceAll("<script>", "");
    description = description.replaceAll("</script>", "");
    description = description.replaceAll("javascript:", "");

    // Limit length
    if (description.length() > 10000) {
        description = description.substring(0, 10000);
    }

    return description;
}
```

### 5. Access Control

Implement proper access control for STIX data:

```java
@Service
public class SecureStixService {

    @PreAuthorize("hasRole('THREAT_ANALYST')")
    public Bundle createBundle(List<BundleableObject> objects) {
        // Only authorized users can create bundles
        return Bundle.builder()
            .addAllObjects(objects)
            .build();
    }

    @PreAuthorize("hasRole('VIEWER')")
    public Bundle readBundle(String bundleId) {
        // Viewers can read but not modify
        return repository.findById(bundleId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteBundle(String bundleId) {
        // Only admins can delete
        repository.delete(bundleId);
    }
}
```

### 6. Logging and Monitoring

Log security-relevant events:

```java
@Component
public class StixSecurityAuditor {

    private static final Logger auditLog = LoggerFactory.getLogger("SECURITY_AUDIT");

    public void auditBundleCreation(Bundle bundle, String userId) {
        auditLog.info("Bundle created: id={}, userId={}, objectCount={}",
            bundle.getId(), userId, bundle.getObjects().size());
    }

    public void auditSuspiciousActivity(String activity, String details) {
        auditLog.warn("Suspicious activity detected: activity={}, details={}",
            activity, details);
    }

    public void auditValidationFailure(String input, Exception e) {
        auditLog.error("Validation failure for input: {}",
            sanitizeForLog(input), e);
    }
}
```

### 7. TLS/SSL for TAXII Communication

Always use TLS when sharing STIX data:

```java
public class SecureTAXIIClient {

    private final SSLContext sslContext;

    public SecureTAXIIClient() throws Exception {
        // Configure SSL/TLS
        sslContext = SSLContext.getInstance("TLSv1.3");

        // Load trusted certificates
        KeyStore trustStore = loadTrustStore();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
    }

    public void sendBundle(Bundle bundle, String endpoint) {
        // Use HTTPS only
        if (!endpoint.startsWith("https://")) {
            throw new SecurityException("HTTPS required for TAXII communication");
        }

        // Send with proper authentication
        // ...
    }
}
```

## Security Features of the Library

### 1. Input Validation

The library automatically validates:
- STIX pattern syntax
- Vocabulary constraints
- Required fields
- Data types
- Relationship constraints

### 2. Immutable Objects

All STIX objects are immutable, preventing:
- Race conditions
- Unauthorized modifications
- State corruption

### 3. Type Safety

Strong typing prevents:
- Type confusion attacks
- Invalid object relationships
- Malformed data structures

### 4. No Code Execution

The library:
- Does not execute STIX patterns
- Does not evaluate expressions
- Does not run embedded code
- Only parses and validates data

## Known Security Considerations

### 1. Pattern Complexity

STIX patterns can be complex. Consider limiting pattern complexity:

```java
public void validatePatternComplexity(String pattern) {
    // Limit pattern length
    if (pattern.length() > 10000) {
        throw new SecurityException("Pattern too complex");
    }

    // Limit nesting depth
    int nestingDepth = countNestingDepth(pattern);
    if (nestingDepth > 10) {
        throw new SecurityException("Pattern nesting too deep");
    }
}
```

### 2. Resource Consumption

Large bundles can consume significant memory:

```java
public void processLargeBundle(InputStream stream) {
    // Stream processing to avoid memory exhaustion
    JsonFactory factory = new JsonFactory();
    try (JsonParser parser = factory.createParser(stream)) {
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            // Process one object at a time
            processNextObject(parser);
        }
    }
}
```

### 3. External References

Validate external references before accessing:

```java
public void validateExternalReference(ExternalReference ref) {
    String url = ref.getUrl();

    // Whitelist allowed domains
    List<String> allowedDomains = Arrays.asList(
        "attack.mitre.org",
        "nvd.nist.gov",
        "cve.mitre.org"
    );

    URI uri = URI.create(url);
    if (!allowedDomains.contains(uri.getHost())) {
        throw new SecurityException("Untrusted external reference");
    }
}
```

## Security Checklist for Deployments

- [ ] Latest library version installed
- [ ] Input validation enabled
- [ ] Size limits configured
- [ ] Access controls implemented
- [ ] Audit logging enabled
- [ ] TLS/SSL configured for network communication
- [ ] Regular security updates applied
- [ ] Monitoring for suspicious patterns
- [ ] Incident response plan in place
- [ ] Regular security assessments

## Contact

For security concerns, contact:
- Email: security@whisper.security
- PGP Key: [Available on request]

For general support:
- Email: support@whisper.security
- GitHub Issues: https://github.com/whisper-security/STIX/issues

## Acknowledgments

We thank the security researchers who have responsibly disclosed vulnerabilities:

| Name | Organization | Vulnerability | Date |
|------|--------------|---------------|------|
| (No vulnerabilities reported yet) | | | |

---

*This security policy is subject to change. Last updated: October 2025*