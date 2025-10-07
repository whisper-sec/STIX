package security.whisper.javastix.pattern.expressions;

import security.whisper.javastix.pattern.PatternExpression;
import security.whisper.javastix.pattern.PatternVisitor;

/**
 * Represents a comparison expression in a STIX pattern.
 * Format: object_path operator value
 */
public class ComparisonExpression implements PatternExpression {

    private final PatternExpression left;
    private final String operator;
    private final PatternExpression right;

    public ComparisonExpression(PatternExpression left, String operator, PatternExpression right) {
        this.left = left;
        this.operator = operator;
        this.right = right;
    }

    public PatternExpression getLeft() {
        return left;
    }

    public String getOperator() {
        return operator;
    }

    public PatternExpression getRight() {
        return right;
    }

    @Override
    public <T> T accept(PatternVisitor<T> visitor) {
        return visitor.visitComparison(this);
    }

    @Override
    public ExpressionType getType() {
        return ExpressionType.COMPARISON;
    }

    @Override
    public String toString() {
        return left + " " + operator + " " + right;
    }
}