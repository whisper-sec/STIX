package security.whisper.javastix.graph.datamarkings;

import security.whisper.javastix.datamarkings.MarkingDefinitionDm;
import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;

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
