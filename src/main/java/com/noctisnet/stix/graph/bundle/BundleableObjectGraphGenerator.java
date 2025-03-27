package com.noctisnet.stix.graph.bundle;

import com.noctisnet.stix.bundle.BundleableObject;
import com.noctisnet.stix.graph.sdo.DomainObjectGraphGenerator;
import com.noctisnet.stix.graph.GraphGenerator;
import com.noctisnet.stix.graph.sro.RelationshipSroGraphGenerator;
import com.noctisnet.stix.graph.sro.SightingSroGraphGenerator;
import com.noctisnet.stix.graph.elements.GraphElement;
import com.noctisnet.stix.sdo.DomainObject;
import com.noctisnet.stix.sro.objects.RelationshipSro;
import com.noctisnet.stix.sro.objects.SightingSro;

import java.util.HashSet;
import java.util.Set;

public class BundleableObjectGraphGenerator implements GraphGenerator {

    private final BundleableObject object;

    public BundleableObjectGraphGenerator(BundleableObject object) {
        this.object = object;
    }

    public BundleableObject getObject() {
        return object;
    }

    public Set<GraphElement> process(){
        Set<GraphElement> items = new HashSet<>();

        Class<? extends BundleableObject> objectClass = object.getClass();

        if (DomainObject.class.isAssignableFrom(objectClass)){
            items.addAll(new DomainObjectGraphGenerator((DomainObject)object).process());

        } else if (RelationshipSro.class.isAssignableFrom(objectClass)){
            items.addAll(new RelationshipSroGraphGenerator((RelationshipSro)object).process());

        } else if (SightingSro.class.isAssignableFrom(objectClass)){
            items.addAll(
                    new SightingSroGraphGenerator((SightingSro) object).process()
            );
        }

        return items;
    }

}
