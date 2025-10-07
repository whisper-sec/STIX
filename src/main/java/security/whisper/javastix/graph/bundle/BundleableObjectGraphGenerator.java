package security.whisper.javastix.graph.bundle;

import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.graph.sdo.DomainObjectGraphGenerator;
import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.sro.RelationshipSroGraphGenerator;
import security.whisper.javastix.graph.sro.SightingSroGraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.sro.objects.RelationshipSro;
import security.whisper.javastix.sro.objects.SightingSro;

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
