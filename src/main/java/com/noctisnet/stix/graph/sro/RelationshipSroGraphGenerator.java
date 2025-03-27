package com.noctisnet.stix.graph.sro;

import com.noctisnet.stix.graph.GraphGenerator;
import com.noctisnet.stix.graph.elements.Edge;
import com.noctisnet.stix.graph.elements.GraphElement;
import com.noctisnet.stix.sro.objects.RelationshipSro;

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
