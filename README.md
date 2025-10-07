# STIX 2.1 Java Library

[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](LICENSE)
[![Java: 8+](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://www.oracle.com/java/)
[![STIX: 2.1](https://img.shields.io/badge/STIX-2.1-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![Maven: 1.0.0](https://img.shields.io/badge/Maven-1.0.0-red.svg)](https://search.maven.org/artifact/security.whisper/stix2.1)

A professional Java implementation of the [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro.html) specification for cyber threat intelligence sharing, designed for both software developers and cybersecurity professionals.

Maintained by [Whisper Security](https://whisper.security)

## 🚀 Features

- **Complete STIX 2.1 Implementation**: Full support for all STIX Domain Objects (SDO), Relationship Objects (SRO), and Cyber Observable Objects (SCO)
- **Type-Safe Builder Pattern**: Intuitive, fluent API for creating STIX objects
- **Automatic Validation**: Built-in validation against STIX 2.1 specification
- **Immutable Objects**: Thread-safe, immutable objects for reliable concurrent processing
- **Comprehensive Documentation**: Professional documentation for developers and security analysts
- **Production Ready**: Thoroughly tested with 100% passing test suite

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
    <version>1.0.0</version>
</dependency>
```

### Gradle

```gradle
implementation 'security.whisper:stix2.1:1.0.0'
```

### Your First STIX Object

```java
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.common.StixInstant;

// Create a threat actor
ThreatActor aptGroup = ThreatActor.builder()
    .name("APT29")
    .addLabel("nation-state")
    .description("Russian state-sponsored threat group")
    .sophistication("advanced")
    .resourceLevel("government")
    .primaryMotivation("espionage")
    .build();

// Create an indicator
Indicator maliciousIP = Indicator.builder()
    .pattern("[ipv4-addr:value = '192.0.2.1']")
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
// Automatically validates against STIX vocabularies
ThreatActor actor = ThreatActor.builder()
    .name("APT1")
    .addLabel("nation-state")     // ✅ Valid
    // .addLabel("super-hacker")   // ❌ Would throw ValidationException
    .build();
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
git clone https://github.com/whisper-security/STIX.git
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
- All [contributors](https://github.com/whisper-security/STIX/graphs/contributors) who have helped improve this library

## 📊 Project Status

- **Current Version**: 1.0.0 (Stable)
- **STIX Version**: 2.1
- **Java Compatibility**: 8, 11, 17, 21
- **Build Status**: ✅ All tests passing
- **Documentation**: ✅ Complete

## 🚦 Roadmap

- [ ] TAXII 2.1 client implementation
- [ ] STIX pattern validator and executor
- [ ] GraphQL API for STIX objects
- [ ] Kotlin DSL support
- [ ] Spring Boot starter module

## 📧 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/whisper-security/STIX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/whisper-security/STIX/discussions)
- **Email**: support@whisper.security
- **Security**: security@whisper.security

## 🔄 Version History

See [CHANGELOG.md](CHANGELOG.md) for a detailed version history.

### Latest Release: v1.0.0
- First stable release
- Complete STIX 2.1 support
- Professional documentation
- BSD 2-Clause License

---

<div align="center">
  <b>Built with ❤️ by <a href="https://whisper.security">Whisper Security</a></b>
  <br>
  <i>Making cyber threat intelligence sharing simple and reliable</i>
</div>