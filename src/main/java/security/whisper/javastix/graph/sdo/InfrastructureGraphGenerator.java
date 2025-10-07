package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.objects.InfrastructureSdo;

import java.util.HashSet;
import java.util.Set;

/**
 * Specialized graph generator for Infrastructure SDO.
 * Adds infrastructure specific metadata to graph nodes.
 */
public class InfrastructureGraphGenerator implements GraphGenerator {

    private final InfrastructureSdo infrastructure;

    public InfrastructureGraphGenerator(InfrastructureSdo infrastructure) {
        this.infrastructure = infrastructure;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateNode());
        return elements;
    }

    private Node generateNode() {
        Node node = new Node(infrastructure.getId(), "infrastructure", null, infrastructure);

        // Add infrastructure specific properties
        node.getData().setNodeLabel(infrastructure.getName());
        node.getData().setNodeColor("#607D8B"); // Blue-grey for infrastructure
        node.getData().setNodeShape("rectangle");
        node.getData().setNodeIcon("infrastructure");

        // Add additional metadata
        node.getData().getAdditionalProperties().put("name", infrastructure.getName());

        if (infrastructure.getDescription() != null) {
            node.getData().getAdditionalProperties().put("description",
                infrastructure.getDescription().orElse(""));
        }

        if (infrastructure.getInfrastructureTypes() != null && !infrastructure.getInfrastructureTypes().isEmpty()) {
            node.getData().getAdditionalProperties().put("infrastructure_types",
                infrastructure.getInfrastructureTypes());

            // Determine infrastructure category
            String category = "unknown";
            for (String type : infrastructure.getInfrastructureTypes()) {
                if (type.contains("command-and-control") || type.contains("c2")) {
                    category = "c2";
                    node.getData().setNodeColor("#E91E63"); // Pink for C2
                    break;
                } else if (type.contains("hosting")) {
                    category = "hosting";
                } else if (type.contains("botnet")) {
                    category = "botnet";
                    node.getData().setNodeColor("#AB47BC"); // Purple for botnet
                }
            }
            node.getData().getAdditionalProperties().put("infrastructure_category", category);
        }

        if (infrastructure.getAliases() != null && !infrastructure.getAliases().isEmpty()) {
            node.getData().getAdditionalProperties().put("aliases", infrastructure.getAliases());
        }

        if (infrastructure.getKillChainPhases() != null && !infrastructure.getKillChainPhases().isEmpty()) {
            node.getData().getAdditionalProperties().put("kill_chain_phases",
                infrastructure.getKillChainPhases());
        }

        if (infrastructure.getFirstSeen() != null) {
            node.getData().getAdditionalProperties().put("first_seen",
                infrastructure.getFirstSeen().orElse(null));
        }

        if (infrastructure.getLastSeen() != null) {
            node.getData().getAdditionalProperties().put("last_seen",
                infrastructure.getLastSeen().orElse(null));
        }

        return node;
    }
}