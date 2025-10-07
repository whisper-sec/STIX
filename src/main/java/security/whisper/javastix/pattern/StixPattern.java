package security.whisper.javastix.pattern;

import java.util.List;
import java.util.Optional;

/**
 * Represents a parsed STIX pattern.
 * STIX patterns are expressions that describe ways to detect cyber observables.
 */
public class StixPattern {

    private final String originalPattern;
    private final PatternExpression expression;
    private final List<String> observableTypes;
    private final boolean valid;
    private final Optional<String> errorMessage;

    public StixPattern(String originalPattern, PatternExpression expression,
                      List<String> observableTypes, boolean valid,
                      Optional<String> errorMessage) {
        this.originalPattern = originalPattern;
        this.expression = expression;
        this.observableTypes = observableTypes;
        this.valid = valid;
        this.errorMessage = errorMessage;
    }

    /**
     * The original pattern string
     */
    public String getOriginalPattern() {
        return originalPattern;
    }

    /**
     * The parsed pattern expression tree
     */
    public PatternExpression getExpression() {
        return expression;
    }

    /**
     * List of observable types referenced in this pattern
     */
    public List<String> getObservableTypes() {
        return observableTypes;
    }

    /**
     * Whether the pattern is syntactically valid
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Error message if pattern is invalid
     */
    public Optional<String> getErrorMessage() {
        return errorMessage;
    }

    @Override
    public String toString() {
        return originalPattern;
    }
}