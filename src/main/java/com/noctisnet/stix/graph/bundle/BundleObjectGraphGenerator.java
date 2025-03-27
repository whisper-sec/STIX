package com.noctisnet.stix.graph.bundle;

import com.noctisnet.stix.bundle.BundleObject;
import com.noctisnet.stix.graph.GraphGenerator;
import com.noctisnet.stix.graph.elements.GraphElement;

import java.util.HashSet;
import java.util.Set;

public class BundleObjectGraphGenerator implements GraphGenerator {

    private final BundleObject object;

    public BundleObjectGraphGenerator(BundleObject object) {
        this.object = object;
    }

    public BundleObject getObject() {
        return object;
    }

    public Set<GraphElement> process(){
        Set<GraphElement> items = new HashSet<>();

        object.getObjects().forEach(o->{
            items.addAll(new BundleableObjectGraphGenerator(o).process());
        });
        return items;
    }

}
