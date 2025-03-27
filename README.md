# STIX 2.x Java Library

A modern Java implementation of the [STIX 2.x](https://oasis-open.github.io/cti-documentation/resources#stix-20-specification) specification for cyber threat intelligence sharing.

## Features

- Full implementation of STIX 2.0 specification
- Flexible and extensible architecture
- Jackson-based serialization/deserialization
- Support for sub-second precision (up to nanosecond level)
- Clean and intuitive builder patterns

## Quick Start

Here's a simple example of creating and handling STIX objects:

```java
// Create a relationship between Attack Pattern and Malware
Relationship relationship = Relationship.builder()
        .relationshipType("uses")
        .created(Instant.now())
        .sourceRef(AttackPattern.builder()
                .name("Attack Pattern Example")
                .build())
        .targetRef(Malware.builder()
                .name("Malware Example")
                .addLabels("worm")
                .build())
        .build();

// Create a bundle with the relationship
Bundle bundle = Bundle.builder()
        .addObjects(relationship)
        .build();

// Serialize to JSON
String json = bundle.toJsonString();

// Parse JSON back to objects
BundleableObject parsed = StixParsers.parseObject(json);
```

## Timestamp Precision

The library supports flexible timestamp precision:

- Default: 3-digit subsecond precision (milliseconds)
- Supported range: 0-9 digits (up to nanosecond precision)
- Preserves original precision when parsing existing JSON
- Configurable output formatting

## Related Projects

- [TAXII-springboot-bpmn](https://github.com/StephenOTT/TAXII-springboot-bpmn): A TAXII server implementation using Spring Boot and BPMN automation
- [CS-AWARE stix2](https://github.com/cs-aware/stix2): Alternative GSON-based implementation

## License

MIT License

Copyright (c) 2024 Noctis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.