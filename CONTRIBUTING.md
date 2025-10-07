# Contributing to STIX 2.1 Java Library

Thank you for your interest in contributing to the STIX 2.1 Java Library! This document provides guidelines and instructions for contributing.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [How to Contribute](#how-to-contribute)
4. [Development Setup](#development-setup)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [Pull Request Process](#pull-request-process)
8. [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. Contributors are expected to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project team at conduct@whisper.security.

## Getting Started

1. **Fork the Repository**: Fork the project on GitHub to your personal account
2. **Clone Your Fork**: `git clone https://github.com/YOUR-USERNAME/STIX.git`
3. **Add Upstream Remote**: `git remote add upstream https://github.com/whisper-security/STIX.git`
4. **Create a Branch**: `git checkout -b feature/your-feature-name`

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear Title**: Descriptive title summarizing the issue
- **Description**: Detailed description of the bug
- **Steps to Reproduce**: Step-by-step instructions to reproduce
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**:
  - Library version
  - Java version
  - Operating system
  - Build tool (Maven/Gradle) version
- **Code Sample**: Minimal reproducible example
- **Stack Trace**: If applicable

Example bug report:

```markdown
### Bug: NullPointerException when creating Indicator without pattern

**Description:**
Creating an Indicator without setting the pattern field throws NPE instead of ValidationException.

**Steps to Reproduce:**
```java
Indicator indicator = Indicator.builder()
    .validFrom(new StixInstant())
    .build();  // NPE here
```

**Expected:** ValidationException with message about missing pattern
**Actual:** NullPointerException

**Environment:**
- Library: 1.0.0
- Java: 11.0.12
- OS: Ubuntu 20.04
- Maven: 3.8.1
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Include:

- **Use Case**: Explain why this enhancement would be useful
- **Current Behavior**: How things work now
- **Proposed Solution**: Your idea for the enhancement
- **Alternative Solutions**: Other approaches considered
- **Additional Context**: Mockups, examples, etc.

### Contributing Code

1. **Find an Issue**: Look for issues tagged `good-first-issue` or `help-wanted`
2. **Comment on Issue**: Let us know you're working on it
3. **Write Code**: Follow our coding standards
4. **Write Tests**: Ensure adequate test coverage
5. **Document Changes**: Update documentation if needed
6. **Submit PR**: Create a pull request

## Development Setup

### Prerequisites

- Java 8 or higher
- Maven 3.6+
- Git
- IDE (IntelliJ IDEA recommended)

### Building the Project

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/STIX.git
cd STIX

# Build
mvn clean install

# Run tests
mvn test

# Generate Javadocs
mvn javadoc:javadoc
```

### IDE Setup

#### IntelliJ IDEA

1. File → Open → Select the project directory
2. Import as Maven project
3. Install Lombok plugin (for Immutables)
4. Enable annotation processing:
   - Settings → Build → Compiler → Annotation Processors
   - Check "Enable annotation processing"

## Coding Standards

### Java Style Guide

We follow the [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html) with these modifications:

- **Indentation**: 4 spaces (not 2)
- **Line Length**: 120 characters maximum
- **Imports**: No wildcard imports

### Code Organization

```java
// Package declaration
package security.whisper.javastix.sdo.objects;

// Import statements (alphabetized within groups)
import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.sdo.DomainObject;

import javax.validation.constraints.NotNull;
import java.util.Set;

/**
 * Class Javadoc with description.
 *
 * @author Your Name
 * @since 1.1.0
 */
public class ExampleClass {
    // Constants
    private static final String CONSTANT = "value";

    // Fields
    private final String field;

    // Constructors
    public ExampleClass(String field) {
        this.field = field;
    }

    // Methods (public, protected, private)
    public String getField() {
        return field;
    }
}
```

### Immutables Conventions

All STIX objects use Immutables library:

```java
@Value.Immutable
@Serial.Version(1L)
@JsonTypeName("example")
@Value.Style(
    typeAbstract = "*Sdo",
    typeImmutable = "*",
    validationMethod = Value.Style.ValidationMethod.NONE
)
public interface ExampleSdo extends DomainObject {

    @JsonProperty("name")
    @NotBlank
    String getName();

    @Value.Default
    @JsonProperty("labels")
    default Set<String> getLabels() {
        return Collections.emptySet();
    }
}
```

### Validation

Use Bean Validation annotations:

```java
@NotNull                    // Never null
@NotBlank                  // Not null, not empty, not whitespace
@Size(min = 1, max = 100)  // Collection or string size
@Pattern(regexp = "...")   // Regex pattern
@Valid                     // Cascade validation
@Vocab(Vocabulary.class)   // STIX vocabulary validation
```

## Testing Guidelines

### Test Structure

```java
@DisplayName("Indicator Tests")  // Descriptive name
class IndicatorTest {

    @Nested
    @DisplayName("Creation Tests")
    class CreationTests {

        @Test
        @DisplayName("Should create valid indicator with required fields")
        void testValidCreation() {
            // Given
            String pattern = "[file:size > 0]";

            // When
            Indicator indicator = Indicator.builder()
                .pattern(pattern)
                .validFrom(new StixInstant())
                .addLabel("malicious-activity")
                .build();

            // Then
            assertNotNull(indicator);
            assertEquals(pattern, indicator.getPattern());
            assertTrue(indicator.getId().startsWith("indicator--"));
        }

        @Test
        @DisplayName("Should fail without required pattern")
        void testMissingPattern() {
            // When/Then
            assertThrows(ValidationException.class, () ->
                Indicator.builder()
                    .validFrom(new StixInstant())
                    .build()
            );
        }
    }
}
```

### Test Coverage

- Minimum 80% code coverage
- All public methods must have tests
- Test both happy path and error cases
- Include edge cases and boundary conditions

### Running Tests

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=IndicatorTest

# Run with coverage
mvn jacoco:prepare-agent test jacoco:report

# View coverage report
open target/site/jacoco/index.html
```

## Pull Request Process

### Before Submitting

1. **Update from Upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run Tests**: Ensure all tests pass
3. **Check Style**: No compiler warnings
4. **Update Documentation**: If applicable
5. **Add Tests**: For new functionality
6. **Update CHANGELOG.md**: Add your changes

### PR Guidelines

#### Title Format
```
type: Brief description (max 50 chars)

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation only
- style: Code style changes
- refactor: Code refactoring
- test: Test additions/changes
- chore: Maintenance tasks
```

Examples:
- `feat: Add support for STIX 2.1 Incidents`
- `fix: Correct validation for Indicator patterns`
- `docs: Update installation guide for Maven`

#### Description Template

```markdown
## Description
Brief description of changes

## Motivation and Context
Why is this change required? What problem does it solve?
Link to issue: #123

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature that breaks existing API)
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] Added new tests for changes
- [ ] Test coverage maintained/improved

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No new warnings
```

### Review Process

1. **Automated Checks**: CI/CD runs tests and style checks
2. **Code Review**: At least one maintainer reviews
3. **Feedback**: Address review comments
4. **Approval**: Maintainer approves
5. **Merge**: Maintainer merges to main

### After Merge

- Delete your feature branch
- Pull latest changes from upstream
- Celebrate your contribution! 🎉

## Security Vulnerabilities

**Do not** open public issues for security vulnerabilities. Instead:

1. Email security@whisper.security
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. Wait for response (within 48 hours)
4. Work with maintainers on fix
5. Get credited in security advisory

## Documentation

### Javadoc Standards

```java
/**
 * Brief description (one line).
 *
 * <p>Detailed description with multiple paragraphs if needed.
 * Use HTML tags for formatting.</p>
 *
 * <pre>{@code
 * // Code example
 * Indicator indicator = Indicator.builder()
 *     .pattern("[file:size > 0]")
 *     .build();
 * }</pre>
 *
 * @param pattern the STIX pattern string
 * @return the created indicator
 * @throws ValidationException if pattern is invalid
 * @since 1.1.0
 * @see RelatedClass
 */
public Indicator createIndicator(String pattern) {
    // Implementation
}
```

### Updating Documentation

- User guides: `docs/user-guide/`
- API docs: Generated from Javadoc
- Examples: `docs/examples/`
- README.md: Keep concise, link to docs

## Release Process

Releases are managed by maintainers:

1. Update version in pom.xml
2. Update CHANGELOG.md
3. Create release tag
4. Deploy to Maven Central
5. Create GitHub release
6. Announce on channels

## Getting Help

- **Discord**: [Join our Discord](https://discord.gg/whisper-security)
- **GitHub Discussions**: For questions and discussions
- **Stack Overflow**: Tag with `stix` and `java`
- **Email**: dev@whisper.security

## Recognition

Contributors are recognized in:
- CHANGELOG.md (for significant contributions)
- GitHub contributors page
- Annual contributor report

## License

By contributing, you agree that your contributions will be licensed under the BSD 2-Clause License.

---

Thank you for contributing to making cyber threat intelligence sharing better! 🛡️