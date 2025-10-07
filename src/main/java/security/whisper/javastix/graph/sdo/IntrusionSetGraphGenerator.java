package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.objects.IntrusionSetSdo;

import java.util.HashSet;
import java.util.Set;

/**
 * Specialized graph generator for Intrusion Set SDO.
 * Adds intrusion set specific metadata to graph nodes.
 */
public class IntrusionSetGraphGenerator implements GraphGenerator {

    private final IntrusionSetSdo intrusionSet;

    public IntrusionSetGraphGenerator(IntrusionSetSdo intrusionSet) {
        this.intrusionSet = intrusionSet;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateNode());
        return elements;
    }

    private Node generateNode() {
        Node node = new Node(intrusionSet.getId(), "intrusion-set", null, intrusionSet);

        // Add intrusion set specific properties
        node.getData().setNodeLabel(intrusionSet.getName());
        node.getData().setNodeColor("#3F51B5"); // Indigo for intrusion sets
        node.getData().setNodeShape("star");
        node.getData().setNodeIcon("intrusion-set");
        node.getData().setNodeSize("large"); // Intrusion sets are important groupings

        // Add additional metadata
        node.getData().getAdditionalProperties().put("name", intrusionSet.getName());

        if (intrusionSet.getDescription() != null) {
            node.getData().getAdditionalProperties().put("description",
                intrusionSet.getDescription().orElse(""));
        }

        if (intrusionSet.getAliases() != null && !intrusionSet.getAliases().isEmpty()) {
            node.getData().getAdditionalProperties().put("aliases", intrusionSet.getAliases());
            node.getData().getAdditionalProperties().put("aliases_count", intrusionSet.getAliases().size());

            // Add APT group indicators if present
            for (String alias : intrusionSet.getAliases()) {
                if (alias.toUpperCase().startsWith("APT")) {
                    node.getData().getAdditionalProperties().put("is_apt_group", true);
                    node.getData().setNodeColor("#B71C1C"); // Dark red for APT groups
                    break;
                }
            }
        }

        if (intrusionSet.getGoals() != null && !intrusionSet.getGoals().isEmpty()) {
            node.getData().getAdditionalProperties().put("goals", intrusionSet.getGoals());
        }

        if (intrusionSet.getResourceLevel() != null) {
            node.getData().getAdditionalProperties().put("resource_level",
                intrusionSet.getResourceLevel().orElse(""));

            // Adjust node size based on resource level
            String resourceLevel = intrusionSet.getResourceLevel().orElse("");
            if (resourceLevel.contains("government") || resourceLevel.contains("organization")) {
                node.getData().setNodeSize("xlarge");
            }
        }

        if (intrusionSet.getPrimaryMotivation() != null) {
            node.getData().getAdditionalProperties().put("primary_motivation",
                intrusionSet.getPrimaryMotivation().orElse(""));
        }

        if (intrusionSet.getSecondaryMotivations() != null && !intrusionSet.getSecondaryMotivations().isEmpty()) {
            node.getData().getAdditionalProperties().put("secondary_motivations",
                intrusionSet.getSecondaryMotivations());
        }

        if (intrusionSet.getFirstSeen() != null) {
            node.getData().getAdditionalProperties().put("first_seen",
                intrusionSet.getFirstSeen().orElse(null));
        }

        if (intrusionSet.getLastSeen() != null) {
            node.getData().getAdditionalProperties().put("last_seen",
                intrusionSet.getLastSeen().orElse(null));
        }

        return node;
    }
}