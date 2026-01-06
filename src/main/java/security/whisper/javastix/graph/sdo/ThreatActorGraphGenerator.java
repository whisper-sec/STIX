package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.objects.ThreatActorSdo;

import java.util.HashSet;
import java.util.Set;

/**
 * Specialized graph generator for Threat Actor SDO.
 * Adds threat actor specific metadata to graph nodes.
 */
public class ThreatActorGraphGenerator implements GraphGenerator {

    private final ThreatActorSdo threatActor;

    public ThreatActorGraphGenerator(ThreatActorSdo threatActor) {
        this.threatActor = threatActor;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateNode());
        return elements;
    }

    private Node generateNode() {
        Node node = new Node(threatActor.getId(), "threat-actor", null, threatActor);

        // Add threat actor specific properties
        node.getData().setNodeLabel(threatActor.getName());
        node.getData().setNodeColor("#F44336"); // Red for threat actors
        node.getData().setNodeShape("octagon");
        node.getData().setNodeIcon("threat-actor");
        node.getData().setNodeSize("large"); // Threat actors are typically important nodes

        // Add additional metadata
        node.getData().getAdditionalProperties().put("name", threatActor.getName());

        if (threatActor.getDescription() != null) {
            node.getData().getAdditionalProperties().put("description",
                threatActor.getDescription().orElse(""));
        }

        // Add threat_actor_types (STIX 2.1)
        if (threatActor.getThreatActorTypes() != null && !threatActor.getThreatActorTypes().isEmpty()) {
            node.getData().getAdditionalProperties().put("threat_actor_types", threatActor.getThreatActorTypes());

            // Set threat level based on threat_actor_types
            String threatLevel = "unknown";
            if (threatActor.getThreatActorTypes().contains("nation-state")) {
                threatLevel = "critical";
            } else if (threatActor.getThreatActorTypes().contains("crime-syndicate")) {
                threatLevel = "high";
            } else if (threatActor.getThreatActorTypes().contains("activist")) {
                threatLevel = "medium";
            }
            node.getData().getAdditionalProperties().put("threat_level", threatLevel);
        }

        // Keep labels as optional common property
        if (threatActor.getLabels() != null && !threatActor.getLabels().isEmpty()) {
            node.getData().getAdditionalProperties().put("labels", threatActor.getLabels());
        }

        if (threatActor.getAliases() != null && !threatActor.getAliases().isEmpty()) {
            node.getData().getAdditionalProperties().put("aliases", threatActor.getAliases());
            node.getData().getAdditionalProperties().put("aliases_count", threatActor.getAliases().size());
        }

        if (threatActor.getRoles() != null && !threatActor.getRoles().isEmpty()) {
            node.getData().getAdditionalProperties().put("roles", threatActor.getRoles());
        }

        if (threatActor.getGoals() != null && !threatActor.getGoals().isEmpty()) {
            node.getData().getAdditionalProperties().put("goals", threatActor.getGoals());
        }

        if (threatActor.getSophistication() != null) {
            node.getData().getAdditionalProperties().put("sophistication",
                threatActor.getSophistication().orElse(""));
        }

        if (threatActor.getResourceLevel() != null) {
            node.getData().getAdditionalProperties().put("resource_level",
                threatActor.getResourceLevel().orElse(""));
        }

        if (threatActor.getPrimaryMotivation() != null) {
            node.getData().getAdditionalProperties().put("primary_motivation",
                threatActor.getPrimaryMotivation().orElse(""));
        }

        return node;
    }
}