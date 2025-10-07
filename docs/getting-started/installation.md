# Installation Guide

This guide walks you through installing the Whisper STIX 2.1 Java Library in your project.

## Prerequisites

- **Java 8** or higher (Java 8, 11, 17, 21 are all supported)
- **Maven 3.6+** or **Gradle 6+** for dependency management
- An IDE such as IntelliJ IDEA, Eclipse, or VS Code (optional but recommended)

### Jakarta EE Compatibility (v1.3.1+)
- Fully compatible with Jakarta EE 9+ environments
- Compatible with Spring Boot 3.x
- Uses Jakarta validation instead of deprecated javax.validation

## Maven Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>security.whisper</groupId>
    <artifactId>stix2.1</artifactId>
    <version>1.3.1</version>
</dependency>
```

### Complete Maven Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>threat-intel-app</artifactId>
    <version>1.0.0</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>security.whisper</groupId>
            <artifactId>stix2.1</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</project>
```

## Gradle Installation

Add the following to your `build.gradle`:

```gradle
dependencies {
    implementation 'security.whisper:stix2.1:1.3.1'
}
```

### Complete Gradle Example

```gradle
plugins {
    id 'java'
    id 'application'
}

group = 'com.example'
version = '1.0.0'

repositories {
    mavenCentral()
}

dependencies {
    implementation 'security.whisper:stix2.1:1.3.1'

    // Optional: Add logging
    implementation 'org.slf4j:slf4j-api:2.0.9'
    implementation 'ch.qos.logback:logback-classic:1.4.11'

    // Testing
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

test {
    useJUnitPlatform()
}
```

## Building from Source

If you want to build the library from source:

```bash
# Clone the repository
git clone https://github.com/whisper-security/STIX.git
cd STIX

# Build with Maven
mvn clean install

# Run tests
mvn test

# Generate documentation
mvn javadoc:javadoc
```

## Dependency Tree

The STIX library includes the following key dependencies:

- **Jackson** (2.18.3) - JSON serialization/deserialization
- **Immutables** (2.7.3) - Immutable value objects
- **Hibernate Validator** (8.0.1.Final) - Jakarta-compatible bean validation
- **Jakarta Validation API** (3.0.2) - Jakarta EE validation specification
- **Expressly** (5.0.0) - Jakarta Expression Language
- **JGraphT** (1.5.2) - Graph analysis capabilities
- **ANTLR4** (4.13.1) - Pattern parsing

## IDE Configuration

### IntelliJ IDEA

1. Open your project
2. File → Project Structure → Libraries
3. Click '+' → From Maven
4. Search for `security.whisper:stix2.1:1.3.1`
5. Click OK

### Eclipse

1. Right-click on your project
2. Maven → Add Dependency
3. Enter Group Id: `security.whisper`
4. Enter Artifact Id: `stix2.1`
5. Enter Version: `1.3.1`
6. Click OK

### VS Code

Add the dependency to your `pom.xml` or `build.gradle` as shown above. VS Code with Java extensions will automatically recognize it.

## Verifying Installation

Create a simple test class to verify the installation:

```java
import security.whisper.javastix.sdo.objects.Indicator;
import security.whisper.javastix.bundle.Bundle;
import security.whisper.javastix.common.StixInstant;

public class InstallationTest {
    public static void main(String[] args) {
        // Create a simple indicator
        Indicator indicator = Indicator.builder()
            .pattern("[ipv4-addr:value = '192.0.2.1']")
            .validFrom(new StixInstant())
            .addLabel("malicious-activity")
            .build();

        // Create a bundle
        Bundle bundle = Bundle.builder()
            .addObject(indicator)
            .build();

        // Print JSON
        System.out.println(bundle.toJsonString());
        System.out.println("Installation successful!");
    }
}
```

If this prints valid STIX JSON and "Installation successful!", your installation is complete.

## Troubleshooting

### Maven Central Sync Issues

If the artifact isn't available immediately, you can use the GitHub Packages repository:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/whisper-security/STIX</url>
    </repository>
</repositories>
```

### Dependency Conflicts

If you encounter dependency conflicts, particularly with Jackson or Guava:

```xml
<dependency>
    <groupId>security.whisper</groupId>
    <artifactId>stix2.1</artifactId>
    <version>1.0.0</version>
    <exclusions>
        <exclusion>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```

### Java Version Issues

Ensure your Java version is compatible:

```bash
java -version  # Should be 1.8 or higher
mvn -version   # Check Maven's Java version
```

## Next Steps

- Follow the [Quick Start Tutorial](quick-start.md) to create your first STIX objects
- Read [Basic Concepts](basic-concepts.md) to understand STIX fundamentals
- Explore [Code Examples](../examples/code-samples/) for real-world usage

## Support

If you encounter issues during installation:

1. Check the [Troubleshooting Guide](../reference/troubleshooting.md)
2. Search [existing issues](https://github.com/whisper-security/STIX/issues)
3. Open a new issue with:
   - Your Java version
   - Build tool and version
   - Complete error message
   - Minimal reproducible example

---

*[Back to Documentation Index](../README.md)*