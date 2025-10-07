package security.whisper.javastix.pattern;

import security.whisper.javastix.pattern.expressions.*;

import java.util.*;

/**
 * Validator for STIX patterns.
 * Validates pattern syntax and semantic correctness.
 */
public class StixPatternValidator {

    // Valid STIX cyber observable types
    private static final Set<String> VALID_OBSERVABLE_TYPES = new HashSet<>(Arrays.asList(
        "artifact", "autonomous-system", "directory", "domain-name",
        "email-addr", "email-message", "file", "ipv4-addr", "ipv6-addr",
        "mac-addr", "mutex", "network-traffic", "process", "software",
        "url", "user-account", "windows-registry-key", "x509-certificate",
        "x-509-certificate"  // Alternative spelling
    ));

    // Valid comparison operators
    private static final Set<String> VALID_OPERATORS = new HashSet<>(Arrays.asList(
        "=", "!=", ">", "<", ">=", "<=",
        "IN", "LIKE", "MATCHES", "ISSUBSET", "ISSUPERSET"
    ));

    /**
     * Validate a STIX pattern string
     */
    public static ValidationResult validate(String patternString) {
        if (patternString == null || patternString.trim().isEmpty()) {
            return new ValidationResult(false, "Pattern cannot be null or empty");
        }

        // Parse the pattern
        StixPattern pattern = StixPatternParser.parse(patternString);

        // Check if parsing succeeded
        if (!pattern.isValid()) {
            return new ValidationResult(false,
                pattern.getErrorMessage().orElse("Failed to parse pattern"));
        }

        // Validate the parsed pattern
        List<String> errors = new ArrayList<>();
        validateExpression(pattern.getExpression(), errors);

        if (!errors.isEmpty()) {
            return new ValidationResult(false, String.join("; ", errors));
        }

        return new ValidationResult(true, "Pattern is valid");
    }

    /**
     * Recursively validate a pattern expression
     */
    private static void validateExpression(PatternExpression expr, List<String> errors) {
        if (expr == null) {
            errors.add("Null expression found");
            return;
        }

        switch (expr.getType()) {
            case OBSERVATION:
                validateObservation((ObservationExpression) expr, errors);
                break;
            case COMPARISON:
                validateComparison((ComparisonExpression) expr, errors);
                break;
            case COMPOUND:
                validateCompound((CompoundExpression) expr, errors);
                break;
            case QUALIFIED:
                validateQualified((QualifiedExpression) expr, errors);
                break;
            case OBJECT_PATH:
                validateObjectPath((ObjectPathExpression) expr, errors);
                break;
            case LITERAL:
                // Literals are generally valid
                break;
            case LIST:
                validateList((ListExpression) expr, errors);
                break;
            default:
                errors.add("Unknown expression type: " + expr.getType());
        }
    }

    /**
     * Validate an observation expression
     */
    private static void validateObservation(ObservationExpression obs, List<String> errors) {
        if (obs.getComparison() == null) {
            errors.add("Observation must contain a comparison");
        } else {
            validateExpression(obs.getComparison(), errors);
        }
    }

    /**
     * Validate a comparison expression
     */
    private static void validateComparison(ComparisonExpression comp, List<String> errors) {
        // Validate operator
        if (!VALID_OPERATORS.contains(comp.getOperator())) {
            errors.add("Invalid operator: " + comp.getOperator());
        }

        // Validate left side (should be object path)
        if (comp.getLeft() == null) {
            errors.add("Comparison left side cannot be null");
        } else if (comp.getLeft().getType() != PatternExpression.ExpressionType.OBJECT_PATH) {
            errors.add("Comparison left side must be an object path");
        } else {
            validateExpression(comp.getLeft(), errors);
        }

        // Validate right side
        if (comp.getRight() == null) {
            errors.add("Comparison right side cannot be null");
        } else {
            validateExpression(comp.getRight(), errors);
        }
    }

    /**
     * Validate a compound expression
     */
    private static void validateCompound(CompoundExpression compound, List<String> errors) {
        if (compound.getLeft() == null || compound.getRight() == null) {
            errors.add("Compound expression must have both left and right expressions");
        } else {
            validateExpression(compound.getLeft(), errors);
            validateExpression(compound.getRight(), errors);
        }
    }

    /**
     * Validate a qualified expression
     */
    private static void validateQualified(QualifiedExpression qual, List<String> errors) {
        if (qual.getObservation() == null) {
            errors.add("Qualified expression must have an observation");
        } else {
            validateExpression(qual.getObservation(), errors);
        }

        // Validate qualifier value based on type
        switch (qual.getQualifier()) {
            case WITHIN:
                validateTimeWindow(qual.getQualifierValue(), errors);
                break;
            case REPEATS:
                validateRepeatCount(qual.getQualifierValue(), errors);
                break;
            case START:
            case STOP:
                validateTimestamp(qual.getQualifierValue(), errors);
                break;
        }
    }

    /**
     * Validate an object path expression
     */
    private static void validateObjectPath(ObjectPathExpression path, List<String> errors) {
        if (path.getObjectType() != null) {
            if (!VALID_OBSERVABLE_TYPES.contains(path.getObjectType())) {
                errors.add("Invalid observable type: " + path.getObjectType());
            }
        }

        if (path.getPropertyPath() == null || path.getPropertyPath().isEmpty()) {
            errors.add("Property path cannot be empty");
        }
    }

    /**
     * Validate a list expression
     */
    private static void validateList(ListExpression list, List<String> errors) {
        if (list.getValues() == null || list.getValues().isEmpty()) {
            errors.add("List cannot be empty");
        } else {
            for (PatternExpression value : list.getValues()) {
                validateExpression(value, errors);
            }
        }
    }

    /**
     * Validate a time window value (e.g., "5 SECONDS")
     */
    private static void validateTimeWindow(String timeWindow, List<String> errors) {
        if (timeWindow == null || !timeWindow.matches("\\d+\\s+(SECONDS?|MINUTES?|HOURS?|DAYS?)")) {
            errors.add("Invalid time window format: " + timeWindow);
        }
    }

    /**
     * Validate a repeat count
     */
    private static void validateRepeatCount(String repeatCount, List<String> errors) {
        try {
            int count = Integer.parseInt(repeatCount);
            if (count < 1) {
                errors.add("Repeat count must be positive: " + repeatCount);
            }
        } catch (NumberFormatException e) {
            errors.add("Invalid repeat count: " + repeatCount);
        }
    }

    /**
     * Validate a timestamp
     */
    private static void validateTimestamp(String timestamp, List<String> errors) {
        // Simple validation - could be enhanced
        if (timestamp == null || !timestamp.matches("t'\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{3})?Z'")) {
            errors.add("Invalid timestamp format: " + timestamp);
        }
    }

    /**
     * Result of pattern validation
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String message;

        public ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public boolean isValid() {
            return valid;
        }

        public String getMessage() {
            return message;
        }
    }
}