package security.whisper.javastix.graph.sro;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.Edge;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.sro.objects.RelationshipSro;

import java.util.HashSet;
import java.util.Set;

public class RelationshipSroGraphGenerator implements GraphGenerator {

    private final RelationshipSro object;

    public RelationshipSroGraphGenerator(RelationshipSro object) {
        this.object = object;
    }

    public RelationshipSro getObject() {
        return object;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateEdge());
        return elements;
    }

    private Edge generateEdge() {
        Edge edge = new Edge(object.getId(),
                object.getType(),
                object.getSourceRef().getId(),
                object.getTargetRef().getId(),
                object);

        edge.getData().setEdgeLabel(object.getRelationshipType());

        edge.getData()
                .getAdditionalProperties()
                .put("relationship_type", object.getRelationshipType());

        return edge;
    }

}
