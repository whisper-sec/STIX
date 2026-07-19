# STIX 2.1 Java Library

[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](LICENSE)
[![Java: 11+](https://img.shields.io/badge/Java-11%2B-orange.svg)](https://www.oracle.com/java/)
[![STIX: 2.1](https://img.shields.io/badge/STIX-2.1-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![Maven Central](https://img.shields.io/maven-central/v/security.whisper/stix2.1.svg)](https://central.sonatype.com/artifact/security.whisper/stix2.1)

A professional Java implementation of the [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro.html) specification for cyber threat intelligence sharing, designed for both software developers and cybersecurity professionals.

Maintained by [Whisper Security](https://whisper.security)

## 🚀 Features

- **Complete STIX 2.1 Implementation**: Full support for all STIX Domain Objects (SDO), Relationship Objects (SRO), and Cyber Observable Objects (SCO)
- **STIX 2.1 Specification Compliant** (v1.3.4): Comprehensive serialization audit ensures all objects serialize correctly as per STIX 2.1 spec
- **Jakarta EE Compatible** (v1.3.2+): Full support for Jakarta EE 9+ and Spring Boot 3.x with Jakarta validation
- **Advanced Graph Analysis** (v1.3.0): JGraphT-powered graph traversal, centrality analysis, and threat intelligence analytics
- **Pattern Support** (v1.2.0): Full ANTLR4-based STIX pattern parser with evaluation capabilities
- **Type-Safe Builder Pattern**: Intuitive, fluent API for creating STIX objects
- **Automatic Validation**: Built-in validation against STIX 2.1 specification
- **Immutable Objects**: Thread-safe, immutable objects for reliable concurrent processing
- **Enhanced Logging**: SLF4J integration for comprehensive debugging and monitoring
- **Production Ready**: Thoroughly tested with extensive test coverage (77+ tests)

## 📚 Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- [Quick Start Guide](docs/getting-started/quick-start.md) - Get started in 5 minutes
- [Developer Guide](docs/user-guide/for-developers.md) - For software engineers
- [Security Analyst Guide](docs/user-guide/for-security-analysts.md) - For cybersecurity professionals
- [API Reference](docs/api-reference/) - Complete API documentation
- [Examples](docs/examples/) - Real-world use cases and code samples

## ⚡ Quick Start

### Maven

```xml
<dependency>
    <groupId>security.whisper</groupId>
    <artifactId>stix2.1</artifactId>
    <version>1.4.2</version>
</dependency>
```

### Gradle

```gradle
implementation 'security.whisper:stix2.1:1.3.8'
```

### Gradle (Kotlin DSL)

```kotlin
implementation("security.whisper:stix2.1:1.3.8")
```

### Your First STIX Object

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.common.StixInstant;

// Create a threat actor (STIX 2.1 compliant)
ThreatActor aptGroup = ThreatActor.builder()
    .name("APT29")
    .addThreatActorType("nation-state")  // Required in STIX 2.1
    .addThreatActorType("spy")
    .description("Russian state-sponsored threat group")
    .sophistication("advanced")
    .resourceLevel("government")
    .primaryMotivation("espionage")
    .build();

// Create an indicator
Indicator maliciousIP = Indicator.builder()
    .pattern("[ipv4-addr:value = '192.0.2.1']")
    .patternType("stix")
    .validFrom(new StixInstant())
    .addLabel("malicious-activity")
    .confidence(95)
    .build();

// Create a relationship
Relationship uses = Relationship.builder()
    .relationshipType("uses")
    .sourceRef(aptGroup)
    .targetRef(maliciousIP)
    .build();

// Bundle everything together
Bundle threatIntel = Bundle.builder()
    .addObject(aptGroup)
    .addObject(maliciousIP)
    .addObject(uses)
    .build();

// Export to JSON for sharing
String json = threatIntel.toJsonString();
System.out.println(json);
```

## 🛡️ Use Cases

### For Security Analysts

- **Threat Intelligence Sharing**: Share IOCs and threat data in standardized format
- **Incident Response**: Document and share incident information
- **Threat Hunting**: Create and distribute hunting patterns
- **Attack Pattern Mapping**: Map observed behaviors to MITRE ATT&CK

### For Developers

- **SIEM Integration**: Import/export threat data to security platforms
- **Threat Feed Processing**: Consume and produce threat intelligence feeds
- **Security Orchestration**: Automate threat intelligence workflows
- **Custom TIP Development**: Build threat intelligence platforms

## 📦 Supported STIX Objects

### Domain Objects (SDO)
✅ Attack Pattern | ✅ Campaign | ✅ Course of Action | ✅ Grouping
✅ Identity | ✅ Indicator | ✅ Infrastructure | ✅ Intrusion Set
✅ Location | ✅ Malware | ✅ Malware Analysis | ✅ Note
✅ Observed Data | ✅ Opinion | ✅ Report | ✅ Threat Actor
✅ Tool | ✅ Vulnerability | ✅ Incident

### Relationship Objects (SRO)
✅ Relationship | ✅ Sighting

### Cyber Observable Objects (SCO)
✅ Artifact | ✅ Autonomous System | ✅ Directory | ✅ Domain Name
✅ Email Address | ✅ Email Message | ✅ File | ✅ IPv4 Address
✅ IPv6 Address | ✅ MAC Address | ✅ Mutex | ✅ Network Traffic
✅ Process | ✅ Software | ✅ URL | ✅ User Account
✅ Windows Registry Key | ✅ X.509 Certificate

## 🔧 Advanced Features

### Vocabulary Validation

```java
// Automatically validates against STIX 2.1 vocabularies
ThreatActor actor = ThreatActor.builder()
    .name("APT1")
    .addThreatActorType("nation-state")  // ✅ Valid (threat-actor-type-ov)
    .addThreatActorType("spy")           // ✅ Valid
    // .addThreatActorType("super-hacker") // ❌ Would fail validation
    .build();

// Available threat actor types (threat-actor-type-ov):
// activist, competitor, crime-syndicate, criminal, hacker,
// insider-accidental, insider-disgruntled, nation-state,
// sensationalist, spy, terrorist, unknown
```

### Pattern Creation

```java
// Create complex STIX patterns
String pattern = "[file:hashes.MD5 = 'abc123' AND " +
                 "file:size > 1000 AND " +
                 "file:name MATCHES '.*\\.exe$']";

Indicator fileIndicator = Indicator.builder()
    .pattern(pattern)
    .validFrom(new StixInstant())
    .validUntil(new StixInstant().plusDays(90))
    .addLabel("malicious-activity")
    .build();
```

### Custom Properties

```java
// Add organization-specific properties
Malware malware = Malware.builder()
    .name("CustomRAT")
    .addLabel("remote-access-trojan")
    .customProperty("x_internal_id", "MAL-2025-001")
    .customProperty("x_detection_rate", "87.5")
    .build();
```

### TAXII 2.1 Pull Client

Pull STIX bundles from a TAXII 2.1 server, page through collections, and feed
the response straight into `StixParsers.parseBundle` - the same entry point
the rest of the library uses.

```java
import security.whisper.javastix.taxii.*;
import security.whisper.javastix.taxii.model.*;
import security.whisper.javastix.bundle.BundleObject;

try (TaxiiClient client = TaxiiClient.builder()
        .baseUrl("https://limo.anomali.com/api/v1/taxii/taxii-discovery-service/")
        .credentials("guest", "guest")
        .build()) {

    Discovery discovery = client.discover();
    ApiRoot root = client.apiRoot(discovery.getApiRoots().get(0));
    List<Collection> collections = client.collections(root);

    TaxiiCursor cursor = TaxiiCursor.begin();
    do {
        TaxiiPage page = client.objects(root, collections.get(0), cursor,
                TaxiiFilter.builder().addType("indicator").limit(100).build());
        BundleObject bundle = page.bundle();   // delegates to StixParsers.parseBundle
        // ... process bundle, persist cursor.toToken() for restart-safe sync
        cursor = page.nextCursor();
    } while (cursor.getAddedAfter().isPresent());
}
```

The HTTP transport is pluggable - pass a `TaxiiHttpClient` to the builder to
swap in Spring `RestClient`, OkHttp, or any other client. The default uses
the JDK 11 `java.net.http.HttpClient` and adds no transitive dependencies.

## 🏗️ Architecture

- **Immutable Objects**: Thread-safe by design using [Immutables](https://immutables.github.io/)
- **Builder Pattern**: Fluent, intuitive object creation
- **Validation Framework**: Automatic validation with [Hibernate Validator](https://hibernate.org/validator/)
- **JSON Processing**: Fast serialization/deserialization with [Jackson](https://github.com/FasterXML/jackson)

## 🧪 Testing

The library includes comprehensive test coverage:

```bash
# Run tests
mvn test

# Generate coverage report
mvn jacoco:prepare-agent test jacoco:report

# View coverage
open target/site/jacoco/index.html
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/whisper-sec/STIX.git
cd STIX

# Build project
mvn clean install

# Run tests
mvn test
```

## 🔒 Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

**Do not** report security vulnerabilities through GitHub issues. Email security@whisper.security instead.

## 📝 License

This project is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OASIS Cyber Threat Intelligence TC](https://www.oasis-open.org/committees/cti/) for the STIX specification
- [MITRE](https://www.mitre.org/) for ATT&CK framework integration
- All [contributors](https://github.com/whisper-sec/STIX/graphs/contributors) who have helped improve this library

## 📊 Project Status

- **Current Version**: 1.4.2 (Stable)
- **STIX Version**: 2.1 (Fully Compliant)
- **Java Compatibility**: 11, 17, 21
- **Build Status**: ✅ Passing
- **Documentation**: ✅ Complete
- **Maven Central**: ✅ [Available](https://central.sonatype.com/artifact/security.whisper/stix2.1)

## 🚦 Roadmap

- [x] TAXII 2.1 client implementation (v1.4.0)
- [x] STIX pattern parser and validator (v1.2.0)
- [x] Graph analysis and traversal (v1.3.0)
- [ ] GraphQL API for STIX objects
- [ ] Kotlin DSL support
- [ ] Spring Boot starter module

## 📧 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/whisper-sec/STIX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/whisper-sec/STIX/discussions)
- **Email**: support@whisper.security
- **Security**: security@whisper.security

## 🔄 Version History

See [CHANGELOG.md](CHANGELOG.md) for a detailed version history.

### Latest Release: v1.4.2
- **Security**: pins patched transitive dependencies - guava `33.4.8-jre` (CVE-2023-2976, CVE-2020-8908), json-smart `2.5.2` (CVE-2024-57699), and test-only commons-text `1.10.0` (CVE-2022-42889). No API or direct-dependency changes; drop-in upgrade from 1.4.1.

### Previous Releases
- **v1.4.1**: Dependency security updates (commons-lang3, json-path, groovy-all)
- **v1.4.0**: TAXII 2.1 pull client (`TaxiiClient`) with cursor-based pagination and pluggable HTTP transport
- **v1.3.8**: STIX 2.1 ThreatActor `threat_actor_types` support
- **v1.3.7**: Fix Immutables dependency configuration
- **v1.3.6**: Add missing STIX 2.1 relationship types
- **v1.3.5**: Fix missing STIX 2.1 relationship types
- **v1.3.4**: STIX 2.1 specification compliance and timestamp fix
- **v1.3.2**: Jakarta EE 9+ compatibility (Spring Boot 3.x support)
- **v1.3.0**: Advanced graph analysis with JGraphT integration
- **v1.2.0**: ANTLR4-based STIX pattern parser and evaluator
- **v1.0.0**: First stable release with complete STIX 2.1 support

---

<div align="center">
  <b>Built with ❤️ by <a href="https://whisper.security">Whisper Security</a></b>
  <br>
  <i>Making cyber threat intelligence sharing simple and reliable</i>
</div>