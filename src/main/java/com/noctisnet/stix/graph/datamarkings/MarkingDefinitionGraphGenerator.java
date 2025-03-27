package com.noctisnet.stix.graph.datamarkings;

import com.noctisnet.stix.datamarkings.MarkingDefinitionDm;
import com.noctisnet.stix.graph.GraphGenerator;
import com.noctisnet.stix.graph.elements.GraphElement;
import com.noctisnet.stix.graph.elements.Node;

import java.util.HashSet;
import java.util.Set;

public class MarkingDefinitionGraphGenerator implements GraphGenerator{

    private final MarkingDefinitionDm object;

    public MarkingDefinitionGraphGenerator(MarkingDefinitionDm object) {
        this.object = object;
    }

    public MarkingDefinitionDm getObject() {
        return object;
    }

    public Set<GraphElement> process(){
        Set<GraphElement> elements = new HashSet<>();

        elements.add(generateNode());
//        elements.addAll(generateEdges());

        return elements;
    }

    private Node generateNode(){
        return new Node(object.getId(), object.getType(), null, object);
    }

//    private Set<Edge> generateEdges() {
//        Set<Edge> edges = new HashSet<>();
//
//        edges.addAll(generateObjectMarkingRefEdges(object.getObjectMarkingRefs()));
//
//        return edges;
//    }

}
