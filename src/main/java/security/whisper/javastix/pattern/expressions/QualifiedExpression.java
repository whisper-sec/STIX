package security.whisper.javastix.pattern.expressions;

import security.whisper.javastix.pattern.PatternExpression;
import security.whisper.javastix.pattern.PatternVisitor;

/**
 * Represents a qualified observation expression in a STIX pattern.
 * Format: observation WITHIN time_window
 */
public class QualifiedExpression implements PatternExpression {

    public enum Qualifier {
        WITHIN, START, STOP, REPEATS
    }

    private final PatternExpression observation;
    private final Qualifier qualifier;
    private final String qualifierValue;

    public QualifiedExpression(PatternExpression observation, Qualifier qualifier, String qualifierValue) {
        this.observation = observation;
        this.qualifier = qualifier;
        this.qualifierValue = qualifierValue;
    }

    public PatternExpression getObservation() {
        return observation;
    }

    public Qualifier getQualifier() {
        return qualifier;
    }

    public String getQualifierValue() {
        return qualifierValue;
    }

    @Override
    public <T> T accept(PatternVisitor<T> visitor) {
        return visitor.visitQualified(this);
    }

    @Override
    public ExpressionType getType() {
        return ExpressionType.QUALIFIED;
    }

    @Override
    public String toString() {
        return observation + " " + qualifier + " " + qualifierValue;
    }
}