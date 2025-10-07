package security.whisper.javastix.pattern.expressions;

import security.whisper.javastix.pattern.PatternExpression;
import security.whisper.javastix.pattern.PatternVisitor;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Represents a list of values in a STIX pattern.
 * Format: (value1, value2, ...)
 */
public class ListExpression implements PatternExpression {

    private final List<PatternExpression> values;

    public ListExpression(List<PatternExpression> values) {
        this.values = values;
    }

    public List<PatternExpression> getValues() {
        return values;
    }

    @Override
    public <T> T accept(PatternVisitor<T> visitor) {
        return visitor.visitList(this);
    }

    @Override
    public ExpressionType getType() {
        return ExpressionType.LIST;
    }

    @Override
    public String toString() {
        String items = values.stream()
            .map(Object::toString)
            .collect(Collectors.joining(", "));
        return "(" + items + ")";
    }
}