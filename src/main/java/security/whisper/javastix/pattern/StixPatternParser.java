package security.whisper.javastix.pattern;

import security.whisper.javastix.pattern.expressions.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for STIX pattern strings.
 * This is a simplified parser that handles basic STIX pattern syntax.
 * Full ANTLR-based parsing would be required for complete STIX pattern support.
 */
public class StixPatternParser {

    // Basic pattern regexes
    private static final Pattern OBSERVATION_PATTERN =
        Pattern.compile("\\[([^\\]]+)\\]");
    private static final Pattern COMPARISON_PATTERN =
        Pattern.compile("([\\w:._\\[\\]]+)\\s*(=|!=|>|<|>=|<=|IN|LIKE|MATCHES|ISSUBSET|ISSUPERSET)\\s*(.+)");
    private static final Pattern OBJECT_PATH_PATTERN =
        Pattern.compile("([a-z-]+):([\\w._\\[\\]]+)");
    private static final Pattern STRING_LITERAL_PATTERN =
        Pattern.compile("'([^']*)'");
    private static final Pattern LIST_PATTERN =
        Pattern.compile("\\(([^)]+)\\)");

    /**
     * Parse a STIX pattern string into a StixPattern object
     */
    public static StixPattern parse(String patternString) {
        if (patternString == null || patternString.trim().isEmpty()) {
            return new StixPattern(
                patternString,
                null,
                Collections.emptyList(),
                false,
                Optional.of("Pattern string cannot be null or empty")
            );
        }

        try {
            // Trim the pattern
            String trimmed = patternString.trim();

            // Parse the expression
            PatternExpression expression = parseExpression(trimmed);

            // Extract observable types
            List<String> observableTypes = extractObservableTypes(expression);

            return new StixPattern(
                patternString,
                expression,
                observableTypes,
                true,
                Optional.empty()
            );
        } catch (Exception e) {
            return new StixPattern(
                patternString,
                null,
                Collections.emptyList(),
                false,
                Optional.of("Failed to parse pattern: " + e.getMessage())
            );
        }
    }

    /**
     * Parse an expression from the pattern string
     */
    private static PatternExpression parseExpression(String expr) {
        expr = expr.trim();

        // Check for observation expression [...]
        if (expr.startsWith("[") && expr.endsWith("]")) {
            String inner = expr.substring(1, expr.length() - 1);
            return parseObservation(inner);
        }

        // Check for compound expressions (AND/OR)
        if (containsLogicalOperator(expr)) {
            return parseCompound(expr);
        }

        // Check for qualified expressions (WITHIN, START, STOP)
        if (containsQualifier(expr)) {
            return parseQualified(expr);
        }

        // Default to parsing as comparison
        return parseComparison(expr);
    }

    /**
     * Parse an observation expression
     */
    private static ObservationExpression parseObservation(String obs) {
        // Parse the comparison inside the observation
        ComparisonExpression comparison = parseComparison(obs);
        return new ObservationExpression(comparison);
    }

    /**
     * Parse a comparison expression
     */
    private static ComparisonExpression parseComparison(String comp) {
        Matcher matcher = COMPARISON_PATTERN.matcher(comp.trim());
        if (matcher.matches()) {
            String leftPath = matcher.group(1);
            String operator = matcher.group(2);
            String rightValue = matcher.group(3).trim();

            ObjectPathExpression left = parseObjectPath(leftPath);
            PatternExpression right = parseValue(rightValue);

            return new ComparisonExpression(left, operator, right);
        }
        throw new IllegalArgumentException("Invalid comparison expression: " + comp);
    }

    /**
     * Parse an object path expression
     */
    private static ObjectPathExpression parseObjectPath(String path) {
        Matcher matcher = OBJECT_PATH_PATTERN.matcher(path.trim());
        if (matcher.matches()) {
            String objectType = matcher.group(1);
            String propertyPath = matcher.group(2);
            return new ObjectPathExpression(objectType, propertyPath);
        }
        // Simple property path without object type prefix
        return new ObjectPathExpression(null, path.trim());
    }

    /**
     * Parse a value expression (literal, list, etc.)
     */
    private static PatternExpression parseValue(String value) {
        value = value.trim();

        // Check for string literal
        Matcher stringMatcher = STRING_LITERAL_PATTERN.matcher(value);
        if (stringMatcher.matches()) {
            return new LiteralExpression(stringMatcher.group(1), LiteralExpression.LiteralType.STRING);
        }

        // Check for list
        if (value.startsWith("(") && value.endsWith(")")) {
            return parseList(value);
        }

        // Check for boolean
        if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false")) {
            return new LiteralExpression(value, LiteralExpression.LiteralType.BOOLEAN);
        }

        // Check for number
        try {
            if (value.contains(".")) {
                Double.parseDouble(value);
                return new LiteralExpression(value, LiteralExpression.LiteralType.FLOAT);
            } else {
                Long.parseLong(value);
                return new LiteralExpression(value, LiteralExpression.LiteralType.INTEGER);
            }
        } catch (NumberFormatException e) {
            // Not a number
        }

        // Default to string without quotes
        return new LiteralExpression(value, LiteralExpression.LiteralType.STRING);
    }

    /**
     * Parse a list expression
     */
    private static ListExpression parseList(String list) {
        String inner = list.substring(1, list.length() - 1);
        String[] items = inner.split(",");
        List<PatternExpression> values = new ArrayList<>();
        for (String item : items) {
            values.add(parseValue(item.trim()));
        }
        return new ListExpression(values);
    }

    /**
     * Parse a compound expression (AND/OR)
     */
    private static CompoundExpression parseCompound(String expr) {
        // Simplified parsing - would need proper precedence handling
        if (expr.contains(" AND ")) {
            String[] parts = expr.split(" AND ", 2);
            PatternExpression left = parseExpression(parts[0]);
            PatternExpression right = parseExpression(parts[1]);
            return new CompoundExpression(CompoundExpression.Operator.AND, left, right);
        } else if (expr.contains(" OR ")) {
            String[] parts = expr.split(" OR ", 2);
            PatternExpression left = parseExpression(parts[0]);
            PatternExpression right = parseExpression(parts[1]);
            return new CompoundExpression(CompoundExpression.Operator.OR, left, right);
        }
        throw new IllegalArgumentException("Invalid compound expression: " + expr);
    }

    /**
     * Parse a qualified expression (WITHIN, START, STOP)
     */
    private static QualifiedExpression parseQualified(String expr) {
        // Simplified parsing for qualified expressions
        if (expr.contains(" WITHIN ")) {
            String[] parts = expr.split(" WITHIN ");
            PatternExpression observation = parseExpression(parts[0]);
            String timeWindow = parts[1].trim();
            return new QualifiedExpression(observation, QualifiedExpression.Qualifier.WITHIN, timeWindow);
        }
        // Add more qualifier parsing as needed
        throw new IllegalArgumentException("Qualified expression parsing not fully implemented: " + expr);
    }

    /**
     * Check if expression contains logical operators
     */
    private static boolean containsLogicalOperator(String expr) {
        return expr.contains(" AND ") || expr.contains(" OR ");
    }

    /**
     * Check if expression contains qualifiers
     */
    private static boolean containsQualifier(String expr) {
        return expr.contains(" WITHIN ") || expr.contains(" START ") ||
               expr.contains(" STOP ") || expr.contains(" REPEATS ");
    }

    /**
     * Extract observable types from the parsed expression
     */
    private static List<String> extractObservableTypes(PatternExpression expression) {
        Set<String> types = new HashSet<>();
        extractObservableTypesRecursive(expression, types);
        return new ArrayList<>(types);
    }

    private static void extractObservableTypesRecursive(PatternExpression expr, Set<String> types) {
        if (expr == null) return;

        if (expr instanceof ObjectPathExpression) {
            ObjectPathExpression path = (ObjectPathExpression) expr;
            if (path.getObjectType() != null) {
                types.add(path.getObjectType());
            }
        } else if (expr instanceof ComparisonExpression) {
            ComparisonExpression comp = (ComparisonExpression) expr;
            extractObservableTypesRecursive(comp.getLeft(), types);
            extractObservableTypesRecursive(comp.getRight(), types);
        } else if (expr instanceof CompoundExpression) {
            CompoundExpression compound = (CompoundExpression) expr;
            extractObservableTypesRecursive(compound.getLeft(), types);
            extractObservableTypesRecursive(compound.getRight(), types);
        } else if (expr instanceof ObservationExpression) {
            ObservationExpression obs = (ObservationExpression) expr;
            extractObservableTypesRecursive(obs.getComparison(), types);
        } else if (expr instanceof QualifiedExpression) {
            QualifiedExpression qual = (QualifiedExpression) expr;
            extractObservableTypesRecursive(qual.getObservation(), types);
        }
    }
}