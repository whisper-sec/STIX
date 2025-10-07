package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.coo.CyberObservableGraphGenerator;
import security.whisper.javastix.graph.elements.Edge;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.objects.ObservedDataSdo;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class ObservedDataGraphGenerator implements GraphGenerator {

    private final ObservedDataSdo object;

    public ObservedDataGraphGenerator(ObservedDataSdo object) {
        this.object = object;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();

        elements.add(generateNode());
        elements.addAll(generateCooElements());

        return elements;
    }

    private Node generateNode() {
        return new Node(object.getId(), object.getType(), null, object);
    }

    public ObservedDataSdo getObject() {
        return object;
    }

    private Set<GraphElement> generateCooElements(){
        Set<GraphElement> elements = new HashSet<>();

        String observedDataId = object.getId();

        object.getObjects().forEach(coo -> {

            // Generate the Cyber Observable node
            Node cooGraphNode = new CyberObservableGraphGenerator(observedDataId, coo).generateNode();
            elements.add(cooGraphNode);

            String uuidPrefix = "ref";
            String uuid =  uuidPrefix + "-" + UUID.randomUUID().toString();
            // Use the Cyber Observable node's ID as the target:
            Edge edge = new Edge(uuid, uuidPrefix, observedDataId, cooGraphNode.getData().getId(), null);

            edge.getData().setEdgeLabel(coo.getType());
            edge.getData().getAdditionalProperties().put("ref_type", "cyber_observable");

            elements.add(edge);
        });

        return elements;
    }

}
