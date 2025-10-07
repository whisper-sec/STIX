package security.whisper.javastix.pattern.expressions;

import security.whisper.javastix.pattern.PatternExpression;
import security.whisper.javastix.pattern.PatternVisitor;

/**
 * Represents a compound expression in a STIX pattern (AND/OR).
 * Format: expression AND/OR expression
 */
public class CompoundExpression implements PatternExpression {

    public enum Operator {
        AND, OR
    }

    private final Operator operator;
    private final PatternExpression left;
    private final PatternExpression right;

    public CompoundExpression(Operator operator, PatternExpression left, PatternExpression right) {
        this.operator = operator;
        this.left = left;
        this.right = right;
    }

    public Operator getOperator() {
        return operator;
    }

    public PatternExpression getLeft() {
        return left;
    }

    public PatternExpression getRight() {
        return right;
    }

    @Override
    public <T> T accept(PatternVisitor<T> visitor) {
        return visitor.visitCompound(this);
    }

    @Override
    public ExpressionType getType() {
        return ExpressionType.COMPOUND;
    }

    @Override
    public String toString() {
        return "(" + left + " " + operator + " " + right + ")";
    }
}