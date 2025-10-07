package security.whisper.javastix.pattern.expressions;

import security.whisper.javastix.pattern.PatternExpression;
import security.whisper.javastix.pattern.PatternVisitor;

/**
 * Represents an observation expression in a STIX pattern.
 * Format: [comparison]
 */
public class ObservationExpression implements PatternExpression {

    private final ComparisonExpression comparison;

    public ObservationExpression(ComparisonExpression comparison) {
        this.comparison = comparison;
    }

    public ComparisonExpression getComparison() {
        return comparison;
    }

    @Override
    public <T> T accept(PatternVisitor<T> visitor) {
        return visitor.visitObservation(this);
    }

    @Override
    public ExpressionType getType() {
        return ExpressionType.OBSERVATION;
    }

    @Override
    public String toString() {
        return "[" + comparison + "]";
    }
}