package security.whisper.javastix.pattern.expressions;

import security.whisper.javastix.pattern.PatternExpression;
import security.whisper.javastix.pattern.PatternVisitor;

/**
 * Represents a literal value expression in a STIX pattern.
 */
public class LiteralExpression implements PatternExpression {

    public enum LiteralType {
        STRING, INTEGER, FLOAT, BOOLEAN, TIMESTAMP, HEX
    }

    private final String value;
    private final LiteralType literalType;

    public LiteralExpression(String value, LiteralType literalType) {
        this.value = value;
        this.literalType = literalType;
    }

    public String getValue() {
        return value;
    }

    public LiteralType getLiteralType() {
        return literalType;
    }

    @Override
    public <T> T accept(PatternVisitor<T> visitor) {
        return visitor.visitLiteral(this);
    }

    @Override
    public ExpressionType getType() {
        return ExpressionType.LITERAL;
    }

    @Override
    public String toString() {
        if (literalType == LiteralType.STRING) {
            return "'" + value + "'";
        }
        return value;
    }
}