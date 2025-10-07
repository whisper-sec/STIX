package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.sdo.objects.*;

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

        // Use specialized generators for each SDO type
        if (AttackPatternSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(new AttackPatternGraphGenerator((AttackPatternSdo) object).process());
        } else if (CampaignSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(new CampaignGraphGenerator((CampaignSdo) object).process());
        } else if (ThreatActorSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(new ThreatActorGraphGenerator((ThreatActorSdo) object).process());
        } else if (MalwareSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(new MalwareGraphGenerator((MalwareSdo) object).process());
        } else if (IndicatorSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(new IndicatorGraphGenerator((IndicatorSdo) object).process());
        } else if (InfrastructureSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(new InfrastructureGraphGenerator((InfrastructureSdo) object).process());
        } else if (IntrusionSetSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(new IntrusionSetGraphGenerator((IntrusionSetSdo) object).process());
        } else if (ObservedDataSdo.class.isAssignableFrom(object.getClass())) {
            elements.addAll(generateObservedDataGraphElements((ObservedDataSdo) object));
        } else {
            // Default generator for other SDOs (Tool, Vulnerability, Report, etc.)
            elements.add(generateDefaultNode());
        }

        return elements;
    }

    public DomainObject getObject() {
        return object;
    }

    private Node generateDefaultNode() {
        Node node = new Node(object.getId(), object.getType(), null, object);

        // Set default properties based on type
        String type = object.getType();
        switch (type) {
            case "tool":
                node.getData().setNodeColor("#00BCD4"); // Cyan for tools
                node.getData().setNodeShape("circle");
                node.getData().setNodeIcon("tool");
                break;
            case "vulnerability":
                node.getData().setNodeColor("#FFEB3B"); // Yellow for vulnerabilities
                node.getData().setNodeShape("ellipse");
                node.getData().setNodeIcon("vulnerability");
                break;
            case "report":
                node.getData().setNodeColor("#795548"); // Brown for reports
                node.getData().setNodeShape("document");
                node.getData().setNodeIcon("report");
                break;
            case "identity":
                node.getData().setNodeColor("#009688"); // Teal for identities
                node.getData().setNodeShape("circle");
                node.getData().setNodeIcon("identity");
                break;
            case "location":
                node.getData().setNodeColor("#8BC34A"); // Light green for locations
                node.getData().setNodeShape("marker");
                node.getData().setNodeIcon("location");
                break;
            case "course-of-action":
                node.getData().setNodeColor("#00E676"); // Green accent for mitigations
                node.getData().setNodeShape("shield");
                node.getData().setNodeIcon("course-of-action");
                break;
            case "grouping":
                node.getData().setNodeColor("#E0E0E0"); // Light grey for groupings
                node.getData().setNodeShape("folder");
                node.getData().setNodeIcon("grouping");
                break;
            case "note":
                node.getData().setNodeColor("#FFF59D"); // Light yellow for notes
                node.getData().setNodeShape("note");
                node.getData().setNodeIcon("note");
                break;
            case "opinion":
                node.getData().setNodeColor("#CE93D8"); // Light purple for opinions
                node.getData().setNodeShape("bubble");
                node.getData().setNodeIcon("opinion");
                break;
            case "incident":
                node.getData().setNodeColor("#FF6B6B"); // Light red for incidents
                node.getData().setNodeShape("alert");
                node.getData().setNodeIcon("incident");
                break;
            case "malware-analysis":
                node.getData().setNodeColor("#FFB74D"); // Light orange for malware analysis
                node.getData().setNodeShape("analysis");
                node.getData().setNodeIcon("malware-analysis");
                break;
            default:
                node.getData().setNodeColor("#90A4AE"); // Blue-grey for unknown
                node.getData().setNodeShape("circle");
        }

        return node;
    }

    private Set<GraphElement> generateObservedDataGraphElements(ObservedDataSdo observedDataSdo) {
        return new ObservedDataGraphGenerator(observedDataSdo).process();
    }

}
