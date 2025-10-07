package security.whisper.javastix.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Helper class for STIX Pattern construction and manipulation.
 * Provides utilities for building, validating, and parsing STIX patterns.
 *
 * @since 1.3.0
 */
public class StixPatternHelper {

    private static final Logger logger = LoggerFactory.getLogger(StixPatternHelper.class);

    /**
     * Common cyber observable types for pattern construction.
     */
    public static final String TYPE_FILE = "file";
    public static final String TYPE_NETWORK = "network-traffic";
    public static final String TYPE_PROCESS = "process";
    public static final String TYPE_URL = "url";
    public static final String TYPE_DOMAIN = "domain-name";
    public static final String TYPE_IPV4 = "ipv4-addr";
    public static final String TYPE_IPV6 = "ipv6-addr";
    public static final String TYPE_EMAIL = "email-message";
    public static final String TYPE_REGISTRY = "windows-registry-key";
    public static final String TYPE_USER = "user-account";

    /**
     * Common comparison operators.
     */
    public static final String OP_EQUALS = "=";
    public static final String OP_NOT_EQUALS = "!=";
    public static final String OP_GREATER = ">";
    public static final String OP_LESS = "<";
    public static final String OP_GREATER_EQUAL = ">=";
    public static final String OP_LESS_EQUAL = "<=";
    public static final String OP_IN = "IN";
    public static final String OP_LIKE = "LIKE";
    public static final String OP_MATCHES = "MATCHES";
    public static final String OP_ISSET = "ISSUBSET";
    public static final String OP_ISSUPERSET = "ISSUPERSET";

    /**
     * Private constructor to prevent instantiation.
     */
    private StixPatternHelper() {
    }

    /**
     * Creates a simple equality pattern.
     *
     * @param objectType The cyber observable type
     * @param property The property to match
     * @param value The value to match
     * @return A STIX pattern string
     */
    public static String createSimplePattern(String objectType, String property, String value) {
        return createPattern(objectType, property, OP_EQUALS, value);
    }

    /**
     * Creates a pattern with a specific operator.
     *
     * @param objectType The cyber observable type
     * @param property The property to match
     * @param operator The comparison operator
     * @param value The value to match
     * @return A STIX pattern string
     */
    public static String createPattern(String objectType, String property, String operator, String value) {
        if (objectType == null || property == null || operator == null || value == null) {
            throw new IllegalArgumentException("All parameters must be non-null");
        }

        String formattedValue = formatValue(value);
        String pattern = String.format("[%s:%s %s %s]", objectType, property, operator, formattedValue);

        logger.debug("Created pattern: {}", pattern);
        return pattern;
    }

    /**
     * Creates a pattern for matching file hashes.
     *
     * @param hashType The hash type (MD5, SHA-256, etc.)
     * @param hashValue The hash value
     * @return A STIX pattern string
     */
    public static String createFileHashPattern(String hashType, String hashValue) {
        String normalizedHashType = hashType.toUpperCase().replace("-", "");
        return createSimplePattern(TYPE_FILE, "hashes." + normalizedHashType, hashValue);
    }

    /**
     * Creates a pattern for matching network traffic.
     *
     * @param srcIp Source IP address
     * @param dstIp Destination IP address
     * @param dstPort Destination port (optional)
     * @return A STIX pattern string
     */
    public static String createNetworkPattern(String srcIp, String dstIp, Integer dstPort) {
        List<String> conditions = new ArrayList<>();

        if (srcIp != null) {
            conditions.add(String.format("%s:src_ref.value = '%s'", TYPE_NETWORK, srcIp));
        }

        if (dstIp != null) {
            conditions.add(String.format("%s:dst_ref.value = '%s'", TYPE_NETWORK, dstIp));
        }

        if (dstPort != null) {
            conditions.add(String.format("%s:dst_port = %d", TYPE_NETWORK, dstPort));
        }

        if (conditions.isEmpty()) {
            throw new IllegalArgumentException("At least one network parameter must be specified");
        }

        String pattern = "[" + String.join(" AND ", conditions) + "]";
        logger.debug("Created network pattern: {}", pattern);
        return pattern;
    }

    /**
     * Creates a pattern for matching processes.
     *
     * @param processName The process name
     * @param commandLine The command line (optional)
     * @return A STIX pattern string
     */
    public static String createProcessPattern(String processName, String commandLine) {
        List<String> conditions = new ArrayList<>();

        if (processName != null) {
            conditions.add(String.format("%s:name = '%s'", TYPE_PROCESS, processName));
        }

        if (commandLine != null) {
            conditions.add(String.format("%s:command_line = '%s'", TYPE_PROCESS, commandLine));
        }

        if (conditions.isEmpty()) {
            throw new IllegalArgumentException("At least one process parameter must be specified");
        }

        String pattern = "[" + String.join(" AND ", conditions) + "]";
        logger.debug("Created process pattern: {}", pattern);
        return pattern;
    }

    /**
     * Creates a pattern for matching URLs.
     *
     * @param url The URL value
     * @return A STIX pattern string
     */
    public static String createUrlPattern(String url) {
        return createSimplePattern(TYPE_URL, "value", url);
    }

    /**
     * Creates a pattern for matching domain names.
     *
     * @param domain The domain name
     * @return A STIX pattern string
     */
    public static String createDomainPattern(String domain) {
        return createSimplePattern(TYPE_DOMAIN, "value", domain);
    }

    /**
     * Creates a pattern for matching IP addresses.
     *
     * @param ipAddress The IP address
     * @return A STIX pattern string
     */
    public static String createIpPattern(String ipAddress) {
        String type = isIPv6(ipAddress) ? TYPE_IPV6 : TYPE_IPV4;
        return createSimplePattern(type, "value", ipAddress);
    }

    /**
     * Creates a pattern for matching email messages.
     *
     * @param from Sender email address (optional)
     * @param to Recipient email address (optional)
     * @param subject Email subject (optional)
     * @return A STIX pattern string
     */
    public static String createEmailPattern(String from, String to, String subject) {
        List<String> conditions = new ArrayList<>();

        if (from != null) {
            conditions.add(String.format("%s:from_ref.value = '%s'", TYPE_EMAIL, from));
        }

        if (to != null) {
            conditions.add(String.format("%s:to_refs[*].value = '%s'", TYPE_EMAIL, to));
        }

        if (subject != null) {
            conditions.add(String.format("%s:subject = '%s'", TYPE_EMAIL, subject));
        }

        if (conditions.isEmpty()) {
            throw new IllegalArgumentException("At least one email parameter must be specified");
        }

        String pattern = "[" + String.join(" AND ", conditions) + "]";
        logger.debug("Created email pattern: {}", pattern);
        return pattern;
    }

    /**
     * Creates a pattern for Windows registry keys.
     *
     * @param key The registry key
     * @param valueName The value name (optional)
     * @param valueData The value data (optional)
     * @return A STIX pattern string
     */
    public static String createRegistryPattern(String key, String valueName, String valueData) {
        List<String> conditions = new ArrayList<>();

        conditions.add(String.format("%s:key = '%s'", TYPE_REGISTRY, key));

        if (valueName != null) {
            conditions.add(String.format("%s:values[*].name = '%s'", TYPE_REGISTRY, valueName));
        }

        if (valueData != null) {
            conditions.add(String.format("%s:values[*].data = '%s'", TYPE_REGISTRY, valueData));
        }

        String pattern = "[" + String.join(" AND ", conditions) + "]";
        logger.debug("Created registry pattern: {}", pattern);
        return pattern;
    }

    /**
     * Combines multiple patterns with AND logic.
     *
     * @param patterns The patterns to combine
     * @return A combined pattern string
     */
    public static String combineWithAnd(String... patterns) {
        if (patterns == null || patterns.length == 0) {
            throw new IllegalArgumentException("At least one pattern must be provided");
        }

        // Remove brackets from individual patterns and combine
        List<String> conditions = Arrays.stream(patterns)
            .map(p -> p.replaceAll("^\\[|\\]$", ""))
            .collect(Collectors.toList());

        String combined = "[" + String.join(" AND ", conditions) + "]";
        logger.debug("Combined {} patterns with AND: {}", patterns.length, combined);
        return combined;
    }

    /**
     * Combines multiple patterns with OR logic.
     *
     * @param patterns The patterns to combine
     * @return A combined pattern string
     */
    public static String combineWithOr(String... patterns) {
        if (patterns == null || patterns.length == 0) {
            throw new IllegalArgumentException("At least one pattern must be provided");
        }

        // Remove brackets from individual patterns and combine
        List<String> conditions = Arrays.stream(patterns)
            .map(p -> p.replaceAll("^\\[|\\]$", ""))
            .collect(Collectors.toList());

        String combined = "[" + String.join(" OR ", conditions) + "]";
        logger.debug("Combined {} patterns with OR: {}", patterns.length, combined);
        return combined;
    }

    /**
     * Creates a pattern with temporal constraints.
     *
     * @param pattern The base pattern
     * @param startTime Start time (optional)
     * @param stopTime Stop time (optional)
     * @param within Time window in seconds (optional)
     * @return A pattern with temporal constraints
     */
    public static String addTemporalConstraints(String pattern, String startTime, String stopTime, Integer within) {
        StringBuilder result = new StringBuilder(pattern);

        if (startTime != null) {
            result.append(" START '").append(startTime).append("'");
        }

        if (stopTime != null) {
            result.append(" STOP '").append(stopTime).append("'");
        }

        if (within != null) {
            result.append(" WITHIN ").append(within).append(" SECONDS");
        }

        String constrainedPattern = result.toString();
        logger.debug("Added temporal constraints to pattern: {}", constrainedPattern);
        return constrainedPattern;
    }

    /**
     * Creates a pattern with FOLLOWEDBY sequence.
     *
     * @param first First pattern
     * @param second Second pattern
     * @param within Time window in seconds (optional)
     * @return A pattern with FOLLOWEDBY
     */
    public static String createFollowedByPattern(String first, String second, Integer within) {
        String pattern = first + " FOLLOWEDBY " + second;

        if (within != null) {
            pattern += " WITHIN " + within + " SECONDS";
        }

        logger.debug("Created FOLLOWEDBY pattern: {}", pattern);
        return pattern;
    }

    /**
     * Creates a pattern with repeating observations.
     *
     * @param pattern The base pattern
     * @param times Number of times to repeat
     * @return A pattern with REPEATS qualifier
     */
    public static String createRepeatingPattern(String pattern, int times) {
        String repeating = pattern + " REPEATS " + times + " TIMES";
        logger.debug("Created repeating pattern: {}", repeating);
        return repeating;
    }

    /**
     * Escapes special characters in pattern values.
     *
     * @param value The value to escape
     * @return The escaped value
     */
    public static String escapeValue(String value) {
        if (value == null) {
            return null;
        }

        return value
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    /**
     * Formats a value for use in a pattern.
     *
     * @param value The value to format
     * @return The formatted value
     */
    private static String formatValue(Object value) {
        if (value == null) {
            return "null";
        }

        if (value instanceof String) {
            return "'" + escapeValue(value.toString()) + "'";
        }

        if (value instanceof Boolean || value instanceof Number) {
            return value.toString();
        }

        if (value instanceof Collection) {
            Collection<?> collection = (Collection<?>) value;
            return "(" + collection.stream()
                .map(StixPatternHelper::formatValue)
                .collect(Collectors.joining(", ")) + ")";
        }

        return "'" + escapeValue(value.toString()) + "'";
    }

    /**
     * Checks if an IP address is IPv6.
     *
     * @param ipAddress The IP address to check
     * @return true if IPv6, false otherwise
     */
    private static boolean isIPv6(String ipAddress) {
        return ipAddress != null && ipAddress.contains(":");
    }

    /**
     * Validates basic pattern syntax.
     *
     * @param pattern The pattern to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidPattern(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return false;
        }

        // Basic validation - check for brackets and basic structure
        if (!pattern.contains("[") || !pattern.contains("]")) {
            return false;
        }

        // Check for balanced brackets
        int openCount = 0;
        int closeCount = 0;
        for (char c : pattern.toCharArray()) {
            if (c == '[') openCount++;
            if (c == ']') closeCount++;
        }

        return openCount == closeCount && openCount > 0;
    }

    /**
     * Extracts observable types from a pattern.
     *
     * @param pattern The pattern to analyze
     * @return Set of observable types found in the pattern
     */
    public static Set<String> extractObservableTypes(String pattern) {
        Set<String> types = new HashSet<>();

        if (pattern == null) {
            return types;
        }

        // Simple regex to find observable types (word before colon)
        Pattern regex = Pattern.compile("\\[?([a-z\\-]+):");
        Matcher matcher = regex.matcher(pattern);

        while (matcher.find()) {
            types.add(matcher.group(1));
        }

        logger.debug("Extracted observable types: {}", types);
        return types;
    }

    /**
     * Builder for complex patterns.
     */
    public static class PatternBuilder {
        private final List<String> conditions = new ArrayList<>();
        private String startTime;
        private String stopTime;
        private Integer within;

        public PatternBuilder addCondition(String objectType, String property, String operator, Object value) {
            String formattedValue = formatValue(value);
            conditions.add(String.format("%s:%s %s %s", objectType, property, operator, formattedValue));
            return this;
        }

        public PatternBuilder addEquality(String objectType, String property, Object value) {
            return addCondition(objectType, property, OP_EQUALS, value);
        }

        public PatternBuilder setStartTime(String startTime) {
            this.startTime = startTime;
            return this;
        }

        public PatternBuilder setStopTime(String stopTime) {
            this.stopTime = stopTime;
            return this;
        }

        public PatternBuilder setWithin(int seconds) {
            this.within = seconds;
            return this;
        }

        public String buildAnd() {
            if (conditions.isEmpty()) {
                throw new IllegalStateException("No conditions added to pattern");
            }

            String pattern = "[" + String.join(" AND ", conditions) + "]";
            return addTemporalConstraints(pattern, startTime, stopTime, within);
        }

        public String buildOr() {
            if (conditions.isEmpty()) {
                throw new IllegalStateException("No conditions added to pattern");
            }

            String pattern = "[" + String.join(" OR ", conditions) + "]";
            return addTemporalConstraints(pattern, startTime, stopTime, within);
        }
    }

    /**
     * Creates a new PatternBuilder instance.
     *
     * @return A new PatternBuilder
     */
    public static PatternBuilder builder() {
        return new PatternBuilder();
    }
}