package security.whisper.javastix.pattern;

import security.whisper.javastix.pattern.expressions.*;

/**
 * Visitor interface for traversing STIX pattern expression trees.
 * Implements the visitor pattern for pattern AST traversal.
 *
 * @param <T> The return type of visit methods
 */
public interface PatternVisitor<T> {

    /**
     * Visit an observation expression
     */
    T visitObservation(ObservationExpression observation);

    /**
     * Visit a comparison expression
     */
    T visitComparison(ComparisonExpression comparison);

    /**
     * Visit a compound expression (AND/OR)
     */
    T visitCompound(CompoundExpression compound);

    /**
     * Visit an object path expression
     */
    T visitObjectPath(ObjectPathExpression path);

    /**
     * Visit a literal value expression
     */
    T visitLiteral(LiteralExpression literal);

    /**
     * Visit a qualified observation expression
     */
    T visitQualified(QualifiedExpression qualified);

    /**
     * Visit a list expression
     */
    T visitList(ListExpression list);
}