package security.whisper.javastix.graph.coo;

import security.whisper.javastix.coo.CyberObservableObject;
import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Generally used by the Observed Data SDO Graph Generator
 */
public class CyberObservableGraphGenerator implements GraphGenerator {

    private final CyberObservableObject object;
    private final String observedDataObjectId;

    public CyberObservableGraphGenerator(String observedDataObjectId, CyberObservableObject object) {
        this.object = object;
        this.observedDataObjectId = observedDataObjectId;
    }

    public CyberObservableObject getObject() {
        return object;
    }

    public String getObservedDataObjectId() {
        return observedDataObjectId;
    }

    public Set<GraphElement> process(){
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateNode());

        return elements;
    }

    // Is public to support custom usage by Observed Data Graph Generator
    public Node generateNode(){
        String uuid = object.getObservableObjectKey() + "--" + UUID.randomUUID().toString();
        String type = "coo-" + object.getType();

        return new Node(uuid, type, null, object);
        //@TODO Refactor to support the parent node prob for sub graph node support
//        return new Node(uuid, type, observedDataObjectId, object);
    }

}
