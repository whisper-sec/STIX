package security.whisper.javastix.pattern.expressions;

import security.whisper.javastix.pattern.PatternExpression;
import security.whisper.javastix.pattern.PatternVisitor;

/**
 * Represents an object path expression in a STIX pattern.
 * Format: object_type:property_path
 */
public class ObjectPathExpression implements PatternExpression {

    private final String objectType;
    private final String propertyPath;

    public ObjectPathExpression(String objectType, String propertyPath) {
        this.objectType = objectType;
        this.propertyPath = propertyPath;
    }

    public String getObjectType() {
        return objectType;
    }

    public String getPropertyPath() {
        return propertyPath;
    }

    @Override
    public <T> T accept(PatternVisitor<T> visitor) {
        return visitor.visitObjectPath(this);
    }

    @Override
    public ExpressionType getType() {
        return ExpressionType.OBJECT_PATH;
    }

    @Override
    public String toString() {
        if (objectType != null) {
            return objectType + ":" + propertyPath;
        }
        return propertyPath;
    }
}