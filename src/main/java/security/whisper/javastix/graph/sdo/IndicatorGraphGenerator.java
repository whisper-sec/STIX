package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.objects.IndicatorSdo;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Specialized graph generator for Indicator SDO.
 * Adds indicator specific metadata to graph nodes.
 */
public class IndicatorGraphGenerator implements GraphGenerator {

    private final IndicatorSdo indicator;

    public IndicatorGraphGenerator(IndicatorSdo indicator) {
        this.indicator = indicator;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateNode());
        return elements;
    }

    private Node generateNode() {
        Node node = new Node(indicator.getId(), "indicator", null, indicator);

        // Add indicator specific properties
        String label = indicator.getName() != null ?
            indicator.getName().orElse("Indicator") : "Indicator";
        node.getData().setNodeLabel(label);

        // Color based on validity status
        String color = determineColorByValidity();
        node.getData().setNodeColor(color);
        node.getData().setNodeShape("square");
        node.getData().setNodeIcon("indicator");

        // Add additional metadata
        if (indicator.getName() != null) {
            node.getData().getAdditionalProperties().put("name", indicator.getName().orElse(""));
        }

        if (indicator.getDescription() != null) {
            node.getData().getAdditionalProperties().put("description",
                indicator.getDescription().orElse(""));
        }

        // Add pattern information
        node.getData().getAdditionalProperties().put("pattern", indicator.getPattern());
        node.getData().getAdditionalProperties().put("pattern_type", indicator.getPatternType());

        // Add validity information
        node.getData().getAdditionalProperties().put("valid_from", indicator.getValidFrom());

        if (indicator.getValidUntil() != null && indicator.getValidUntil().isPresent()) {
            node.getData().getAdditionalProperties().put("valid_until", indicator.getValidUntil().get());
        }

        // Add validity status
        String validityStatus = determineValidityStatus();
        node.getData().getAdditionalProperties().put("validity_status", validityStatus);

        if (indicator.getIndicatorTypes() != null && !indicator.getIndicatorTypes().isEmpty()) {
            node.getData().getAdditionalProperties().put("indicator_types", indicator.getIndicatorTypes());
        }

        if (indicator.getLabels() != null && !indicator.getLabels().isEmpty()) {
            node.getData().getAdditionalProperties().put("labels", indicator.getLabels());
        }

        if (indicator.getConfidence() != null && indicator.getConfidence().isPresent()) {
            int confidence = indicator.getConfidence().get();
            node.getData().getAdditionalProperties().put("confidence", confidence);

            // Set confidence level
            String confidenceLevel;
            if (confidence >= 75) {
                confidenceLevel = "high";
            } else if (confidence >= 50) {
                confidenceLevel = "medium";
            } else {
                confidenceLevel = "low";
            }
            node.getData().getAdditionalProperties().put("confidence_level", confidenceLevel);
        }

        if (indicator.getKillChainPhases() != null && !indicator.getKillChainPhases().isEmpty()) {
            node.getData().getAdditionalProperties().put("kill_chain_phases",
                indicator.getKillChainPhases());
        }

        // Extract pattern observable types if our pattern parser is available
        try {
            security.whisper.javastix.pattern.StixPattern pattern =
                security.whisper.javastix.pattern.StixPatternParser.parse(indicator.getPattern());
            if (pattern.isValid() && !pattern.getObservableTypes().isEmpty()) {
                node.getData().getAdditionalProperties().put("observable_types",
                    pattern.getObservableTypes());
            }
        } catch (Exception e) {
            // Pattern parsing failed, continue without observable types
        }

        return node;
    }

    private String determineColorByValidity() {
        String validityStatus = determineValidityStatus();
        switch (validityStatus) {
            case "active":
                return "#4CAF50"; // Green for active
            case "expired":
                return "#9E9E9E"; // Grey for expired
            case "future":
                return "#2196F3"; // Blue for future
            default:
                return "#FFC107"; // Amber for unknown
        }
    }

    private String determineValidityStatus() {
        // Simplified validity check - in production, this would compare with current time
        if (indicator.getValidUntil() != null && indicator.getValidUntil().isPresent()) {
            // Check if expired (simplified - would need actual date comparison)
            return "active"; // Default to active for now
        }
        return "active";
    }
}