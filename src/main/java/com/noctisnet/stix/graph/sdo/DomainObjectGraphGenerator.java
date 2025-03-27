package com.noctisnet.stix.graph.sdo;

import com.noctisnet.stix.graph.GraphGenerator;
import com.noctisnet.stix.graph.elements.GraphElement;
import com.noctisnet.stix.graph.elements.Node;
import com.noctisnet.stix.sdo.DomainObject;
import com.noctisnet.stix.sdo.objects.ObservedDataSdo;

import java.util.HashSet;
import java.util.Set;

public class DomainObjectGraphGenerator implements GraphGenerator {

    private final DomainObject object;

    public DomainObjectGraphGenerator(DomainObject object) {
        this.object = object;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();

        if (ObservedDataSdo.class.isAssignableFrom(object.getClass())){
            elements.addAll(generateObservedDataGraphElements((ObservedDataSdo)object));
        } else {
            //@TODO Add various support for the other SDOs
            elements.add(generateNode());
        }

        return elements;
    }

    public DomainObject getObject() {
        return object;
    }

    private Node generateNode() {
        return new Node(object.getId(), object.getType(), null, object);
    }

    private Set<GraphElement> generateObservedDataGraphElements(ObservedDataSdo observedDataSdo){
        return new ObservedDataGraphGenerator(observedDataSdo).process();
    }

}
