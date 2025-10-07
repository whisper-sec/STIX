package security.whisper.javastix.graph;

import org.jgrapht.graph.DefaultWeightedEdge;
import security.whisper.javastix.sro.objects.RelationshipSro;

import java.util.Objects;

/**
 * Represents a STIX relationship as an edge in a JGraphT graph.
 * Extends DefaultWeightedEdge to support weighted graph algorithms.
 *
 * @since 1.3.0
 */
public class StixRelationship extends DefaultWeightedEdge {

    private final RelationshipSro relationship;
    private final String relationshipType;
    private final String id;

    /**
     * Creates a new StixRelationship edge from a STIX RelationshipSro.
     *
     * @param relationship The STIX relationship object
     */
    public StixRelationship(RelationshipSro relationship) {
        this.relationship = Objects.requireNonNull(relationship, "Relationship cannot be null");
        this.relationshipType = relationship.getRelationshipType();
        this.id = relationship.getId();
    }

    /**
     * Gets the underlying STIX relationship object.
     *
     * @return The RelationshipSro
     */
    public RelationshipSro getRelationship() {
        return relationship;
    }

    /**
     * Gets the relationship type (e.g., "uses", "attributed-to").
     *
     * @return The relationship type
     */
    public String getRelationshipType() {
        return relationshipType;
    }

    /**
     * Gets the unique identifier of this relationship.
     *
     * @return The relationship ID
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the description of the relationship if available.
     *
     * @return The description or null if not present
     */
    public String getDescription() {
        return relationship.getDescription().orElse(null);
    }

    /**
     * Override getWeight to use a default weight for algorithms.
     * In STIX 2.1, relationships don't have a standard confidence field.
     *
     * @return Default weight of 1.0
     */
    @Override
    protected double getWeight() {
        // Use a default weight since RelationshipSro doesn't have confidence
        return 1.0;
    }

    @Override
    public String toString() {
        return String.format("%s -[%s]-> %s",
            getSource(),
            relationshipType,
            getTarget());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof StixRelationship)) return false;
        StixRelationship that = (StixRelationship) o;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}