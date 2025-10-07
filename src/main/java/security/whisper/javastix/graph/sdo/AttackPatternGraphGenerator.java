package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.objects.AttackPatternSdo;

import java.util.HashSet;
import java.util.Set;

/**
 * Specialized graph generator for Attack Pattern SDO.
 * Adds attack pattern specific metadata to graph nodes.
 */
public class AttackPatternGraphGenerator implements GraphGenerator {

    private final AttackPatternSdo attackPattern;

    public AttackPatternGraphGenerator(AttackPatternSdo attackPattern) {
        this.attackPattern = attackPattern;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateNode());
        return elements;
    }

    private Node generateNode() {
        Node node = new Node(attackPattern.getId(), "attack-pattern", null, attackPattern);

        // Add attack pattern specific properties
        node.getData().setNodeLabel(attackPattern.getName());
        node.getData().setNodeColor("#FF5722"); // Orange-red for attack patterns
        node.getData().setNodeShape("diamond");
        node.getData().setNodeIcon("attack");

        // Add additional metadata
        node.getData().getAdditionalProperties().put("name", attackPattern.getName());

        if (attackPattern.getDescription() != null) {
            node.getData().getAdditionalProperties().put("description",
                attackPattern.getDescription().orElse(""));
        }

        if (attackPattern.getKillChainPhases() != null && !attackPattern.getKillChainPhases().isEmpty()) {
            node.getData().getAdditionalProperties().put("kill_chain_phases",
                attackPattern.getKillChainPhases());
        }

        if (attackPattern.getExternalReferences() != null && !attackPattern.getExternalReferences().isEmpty()) {
            node.getData().getAdditionalProperties().put("external_references_count",
                attackPattern.getExternalReferences().size());
        }

        // Add CAPEC ID if available in external references
        if (attackPattern.getExternalReferences() != null) {
            attackPattern.getExternalReferences().stream()
                .filter(ref -> "capec".equalsIgnoreCase(ref.getSourceName()))
                .findFirst()
                .ifPresent(ref -> {
                    node.getData().getAdditionalProperties().put("capec_id", ref.getExternalId());
                });
        }

        return node;
    }
}