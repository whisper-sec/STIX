# Changelog

All notable changes to the STIX 2.1 Java Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-07

### 🎉 Major Release - Production Ready

This is the first stable release of the STIX 2.1 Java Library, providing comprehensive support for creating, parsing, and sharing cyber threat intelligence in STIX 2.1 format.

### Added
- **Comprehensive Documentation**
  - Professional documentation for developers and security analysts
  - Quick start guides and tutorials
  - API reference documentation
  - Security use cases and examples
  - Integration patterns for SIEM and threat intelligence platforms

- **License Change**
  - Changed from MIT to BSD 2-Clause License for better commercial compatibility

### Changed
- **STIX Specification Version**
  - Updated from STIX 2.0 to STIX 2.1 specification
  - Fixed spec_version field to correctly report "2.1"

### Fixed
- **Critical Validation Fixes**
  - Fixed null-returning collection fields in 20+ SDO/SRO interfaces
  - Added `@Value.Default` annotations for proper Immutables builder generation
  - Fixed `Collections.emptySet()` returns instead of null for all collection fields
  - Fixed vocabulary validation for Optional<String> fields
  - Fixed StixVocabValidatorCollection to handle null inputs

- **Test Coverage**
  - All 28 tests now passing (100% pass rate)
  - Fixed vocabulary term usage in tests
  - Added required fields to test objects
  - Fixed Report and ObservedData test object creation

## [0.3.0] - 2025-10-06 (Pre-release)

### Fixed
- Fixed missing Indicator properties
- Fixed Cyber Observable Object bundling issues
- Improved COO ID generation
- Enhanced StixInstant API

## [0.2.0] - 2025-10-06 (Pre-release)

### Fixed
- **Bundle Objects Support** - Critical fix for Bundle.getObjects() to enable proper builder methods
- **Vocabulary Pattern Standardization** - Fixed InfrastructureTypes to implement StixVocabulary interface
- **Builder Method Generation** - Immutables now properly generates addObject(), addObjects(), and addAllObjects() methods

### Changed
- Made Bundle.getObjects() abstract instead of default method returning null
- Rewrote InfrastructureTypes vocabulary class to follow standard pattern

## [0.1.0] - 2025-10-05 (Initial Pre-release)

### Added
- Initial implementation of STIX 2.0 specification
- Support for all STIX Domain Objects (SDO)
- Support for STIX Relationship Objects (SRO)
- Support for Cyber Observable Objects (SCO)
- Bundle creation and management
- JSON serialization/deserialization
- Vocabulary validation
- Immutable object pattern with builders

### Known Issues
- Bundle objects cannot be properly added (fixed in 0.2.0)
- Some vocabulary classes not following standard pattern (fixed in 0.2.0)

## Migration Guide

### Migrating from 0.3.0 to 1.0.0

No breaking changes. The following improvements have been made:

1. **Documentation**: Comprehensive documentation is now available in the `docs/` directory
2. **License**: Changed to BSD 2-Clause (update your license compliance if needed)
3. **Stability**: All critical bugs fixed, production ready

### Migrating from 0.2.0 to 1.0.0

1. **STIX Version**: Library now correctly reports STIX 2.1 (was 2.0)
2. **Validation**: Stricter validation of vocabulary terms
3. **Required Fields**: Some objects now properly enforce required fields

Example migration:
```java
// Old (might have worked incorrectly)
Report report = Report.builder()
    .name("Report")
    .published(new StixInstant())
    // Missing required label!
    .build();

// New (correct)
Report report = Report.builder()
    .name("Report")
    .published(new StixInstant())
    .addLabel("threat-report")  // Now required
    .build();
```

### Migrating from 0.1.0 to 1.0.0

Major changes required:

1. **Bundle Creation**: Use builder methods instead of direct manipulation
```java
// Old (didn't work)
Bundle bundle = Bundle.builder().build();
// Could not add objects!

// New
Bundle bundle = Bundle.builder()
    .addObject(indicator)
    .addObject(malware)
    .build();
```

2. **Vocabulary Classes**: Update any custom vocabulary implementations
3. **Validation**: Handle ValidationException for invalid STIX objects

## Deprecation Notice

No deprecated features in this release.

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## Support

- GitHub Issues: https://github.com/whisper-security/STIX/issues
- Documentation: See `docs/` directory
- Email: support@whisper.security

---

*For detailed changes, see the [Git commit history](https://github.com/whisper-security/STIX/commits/main)*