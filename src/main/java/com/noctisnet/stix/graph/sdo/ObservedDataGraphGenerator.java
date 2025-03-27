package com.noctisnet.stix.graph.sdo;

import com.noctisnet.stix.graph.GraphGenerator;
import com.noctisnet.stix.graph.coo.CyberObservableGraphGenerator;
import com.noctisnet.stix.graph.elements.Edge;
import com.noctisnet.stix.graph.elements.GraphElement;
import com.noctisnet.stix.graph.elements.Node;
import com.noctisnet.stix.sdo.objects.ObservedDataSdo;

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
