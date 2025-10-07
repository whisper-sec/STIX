package security.whisper.javastix.pattern;

/**
 * Base interface for STIX pattern expressions.
 * Pattern expressions form an Abstract Syntax Tree (AST) representing the pattern structure.
 */
public interface PatternExpression {

    /**
     * Accept a visitor for pattern traversal
     */
    <T> T accept(PatternVisitor<T> visitor);

    /**
     * Get the expression type
     */
    ExpressionType getType();

    /**
     * Expression types in STIX patterns
     */
    enum ExpressionType {
        OBSERVATION,           // Observation expression [file:hashes.MD5 = '...']
        COMPARISON,            // Comparison expression (=, !=, >, <, etc.)
        COMPOUND,              // Compound expression (AND, OR)
        QUALIFIED,             // Qualified observation (WITHIN, START, STOP)
        REPEATED,              // Repeated observation (REPEATS)
        FOLLOWED_BY,           // Followed by observation
        OBJECT_PATH,           // Object path (e.g., file:hashes.MD5)
        LITERAL,               // Literal value
        LIST,                  // List of values
        LIKE,                  // Pattern matching with LIKE
        MATCHES,               // Regular expression matching
        IN,                    // Value in list
        ISSUBSET,              // Subset comparison
        ISSUPERSET             // Superset comparison
    }
}