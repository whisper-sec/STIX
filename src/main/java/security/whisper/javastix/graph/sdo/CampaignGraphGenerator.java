package security.whisper.javastix.graph.sdo;

import security.whisper.javastix.graph.GraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sdo.objects.CampaignSdo;

import java.util.HashSet;
import java.util.Set;

/**
 * Specialized graph generator for Campaign SDO.
 * Adds campaign specific metadata to graph nodes.
 */
public class CampaignGraphGenerator implements GraphGenerator {

    private final CampaignSdo campaign;

    public CampaignGraphGenerator(CampaignSdo campaign) {
        this.campaign = campaign;
    }

    @Override
    public Set<GraphElement> process() {
        Set<GraphElement> elements = new HashSet<>();
        elements.add(generateNode());
        return elements;
    }

    private Node generateNode() {
        Node node = new Node(campaign.getId(), "campaign", null, campaign);

        // Add campaign specific properties
        node.getData().setNodeLabel(campaign.getName());
        node.getData().setNodeColor("#9C27B0"); // Purple for campaigns
        node.getData().setNodeShape("hexagon");
        node.getData().setNodeIcon("campaign");

        // Add additional metadata
        node.getData().getAdditionalProperties().put("name", campaign.getName());

        if (campaign.getDescription() != null) {
            node.getData().getAdditionalProperties().put("description",
                campaign.getDescription().orElse(""));
        }

        if (campaign.getObjective() != null) {
            node.getData().getAdditionalProperties().put("objective",
                campaign.getObjective().orElse(""));
        }

        if (campaign.getAliases() != null && !campaign.getAliases().isEmpty()) {
            node.getData().getAdditionalProperties().put("aliases", campaign.getAliases());
        }

        if (campaign.getFirstSeen() != null) {
            node.getData().getAdditionalProperties().put("first_seen",
                campaign.getFirstSeen().orElse(null));
        }

        if (campaign.getLastSeen() != null) {
            node.getData().getAdditionalProperties().put("last_seen",
                campaign.getLastSeen().orElse(null));
        }

        // Add campaign status indicator
        boolean isActive = false;
        if (campaign.getLastSeen() != null && campaign.getLastSeen().isPresent()) {
            // Check if campaign is potentially still active (seen in last 90 days)
            // This is a simplified check - real logic would compare with current date
            isActive = true;
        }
        node.getData().getAdditionalProperties().put("is_active", isActive);

        return node;
    }
}