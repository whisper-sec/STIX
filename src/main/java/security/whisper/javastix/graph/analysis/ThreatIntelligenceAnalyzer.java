package security.whisper.javastix.graph.analysis;

import org.jgrapht.Graph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.graph.StixGraph;
import security.whisper.javastix.graph.StixRelationship;
import security.whisper.javastix.graph.traversal.StixGraphTraversal;
import security.whisper.javastix.sdo.objects.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Provides threat intelligence specific analysis for STIX graphs.
 * Includes attack pattern analysis, threat actor profiling, and indicator correlation.
 *
 * @since 1.3.0
 */
public class ThreatIntelligenceAnalyzer {

    private static final Logger logger = LoggerFactory.getLogger(ThreatIntelligenceAnalyzer.class);

    private final StixGraph stixGraph;
    private final Graph<BundleableObject, StixRelationship> graph;
    private final StixGraphTraversal traversal;

    /**
     * Creates a new threat intelligence analyzer for the given STIX graph.
     *
     * @param stixGraph The STIX graph to analyze
     */
    public ThreatIntelligenceAnalyzer(StixGraph stixGraph) {
        this.stixGraph = Objects.requireNonNull(stixGraph, "StixGraph cannot be null");
        this.graph = stixGraph.getGraph();
        this.traversal = new StixGraphTraversal(stixGraph);
    }

    /**
     * Finds attack sequences (chains of attack patterns).
     *
     * @return List of attack pattern sequences
     */
    public List<List<AttackPattern>> findAttackSequences() {
        logger.debug("Finding attack sequences");

        List<AttackPattern> attackPatterns = stixGraph.getObjectsByType(AttackPattern.class);
        List<List<AttackPattern>> sequences = new ArrayList<>();

        for (AttackPattern start : attackPatterns) {
            // Find attack patterns connected through relationships
            Set<BundleableObject> reachable = traversal.findWithinHops(start.getId(), 3, true);

            List<AttackPattern> sequence = reachable.stream()
                .filter(obj -> obj instanceof AttackPattern && !obj.equals(start))
                .map(obj -> (AttackPattern) obj)
                .collect(Collectors.toList());

            if (!sequence.isEmpty()) {
                sequence.add(0, start); // Add start at the beginning
                sequences.add(sequence);
            }
        }

        logger.info("Found {} attack sequences", sequences.size());
        return sequences;
    }

    /**
     * Maps attack patterns to the malware that uses them.
     *
     * @return Map of attack patterns to sets of malware
     */
    public Map<AttackPattern, Set<Malware>> getAttackPatternToMalware() {
        logger.debug("Mapping attack patterns to malware");

        Map<AttackPattern, Set<Malware>> mapping = new HashMap<>();
        List<AttackPattern> attackPatterns = stixGraph.getObjectsByType(AttackPattern.class);

        for (AttackPattern pattern : attackPatterns) {
            Set<BundleableObject> related = traversal.findByRelationshipType(
                pattern.getId(), "uses");

            Set<Malware> malware = related.stream()
                .filter(obj -> obj instanceof Malware)
                .map(obj -> (Malware) obj)
                .collect(Collectors.toSet());

            if (!malware.isEmpty()) {
                mapping.put(pattern, malware);
            }
        }

        logger.info("Mapped {} attack patterns to malware", mapping.size());
        return mapping;
    }

    /**
     * Gets all infrastructure associated with a threat actor.
     *
     * @param actorId The threat actor ID
     * @return Set of infrastructure objects (domains, IPs, tools, etc.)
     */
    public Set<BundleableObject> getThreatActorInfrastructure(String actorId) {
        logger.debug("Getting infrastructure for threat actor: {}", actorId);

        BundleableObject actor = stixGraph.getObject(actorId);
        if (!(actor instanceof ThreatActor)) {
            logger.warn("Object {} is not a threat actor", actorId);
            return Collections.emptySet();
        }

        Set<BundleableObject> infrastructure = new HashSet<>();

        // Find directly used tools and malware
        infrastructure.addAll(traversal.findByRelationshipType(actorId, "uses"));

        // Find attributed campaigns
        Set<BundleableObject> campaigns = traversal.findByRelationshipType(
            actorId, "attributed-to");

        // For each campaign, find its infrastructure
        for (BundleableObject campaign : campaigns) {
            infrastructure.addAll(traversal.findByRelationshipType(
                campaign.getId(), "uses"));
        }

        // Filter to keep only infrastructure-related objects
        infrastructure = infrastructure.stream()
            .filter(obj -> obj instanceof Tool ||
                          obj instanceof Malware ||
                          obj instanceof Infrastructure ||
                          obj.getType().startsWith("domain") ||
                          obj.getType().startsWith("ipv"))
            .collect(Collectors.toSet());

        logger.info("Found {} infrastructure objects for threat actor {}",
            infrastructure.size(), actorId);
        return infrastructure;
    }

    /**
     * Finds threat actors related to a given threat actor.
     *
     * @param actorId The threat actor ID
     * @return Set of related threat actors
     */
    public Set<ThreatActor> findRelatedThreatActors(String actorId) {
        logger.debug("Finding threat actors related to: {}", actorId);

        Set<ThreatActor> related = new HashSet<>();

        // Find actors sharing the same campaigns
        Set<BundleableObject> campaigns = traversal.findByRelationshipType(
            actorId, "attributed-to");

        for (BundleableObject campaign : campaigns) {
            Set<BundleableObject> upstream = traversal.getUpstream(campaign.getId());
            related.addAll(upstream.stream()
                .filter(obj -> obj instanceof ThreatActor && !obj.getId().equals(actorId))
                .map(obj -> (ThreatActor) obj)
                .collect(Collectors.toSet()));
        }

        // Find actors sharing the same infrastructure
        Set<BundleableObject> infrastructure = getThreatActorInfrastructure(actorId);
        for (BundleableObject infra : infrastructure) {
            Set<BundleableObject> upstream = traversal.getUpstream(infra.getId());
            related.addAll(upstream.stream()
                .filter(obj -> obj instanceof ThreatActor && !obj.getId().equals(actorId))
                .map(obj -> (ThreatActor) obj)
                .collect(Collectors.toSet()));
        }

        logger.info("Found {} related threat actors for {}", related.size(), actorId);
        return related;
    }

    /**
     * Finds indicators that correlate with a given indicator.
     *
     * @param indicatorId The indicator ID
     * @return Set of correlated indicators
     */
    public Set<Indicator> findCorrelatedIndicators(String indicatorId) {
        logger.debug("Finding indicators correlated with: {}", indicatorId);

        BundleableObject indicator = stixGraph.getObject(indicatorId);
        if (!(indicator instanceof Indicator)) {
            return Collections.emptySet();
        }

        Set<Indicator> correlated = new HashSet<>();

        // Find indicators that indicate the same objects
        Set<BundleableObject> indicated = traversal.findByRelationshipType(
            indicatorId, "indicates");

        for (BundleableObject obj : indicated) {
            Set<BundleableObject> upstream = traversal.getUpstream(obj.getId());
            correlated.addAll(upstream.stream()
                .filter(o -> o instanceof Indicator && !o.getId().equals(indicatorId))
                .map(o -> (Indicator) o)
                .collect(Collectors.toSet()));
        }

        logger.info("Found {} correlated indicators", correlated.size());
        return correlated;
    }

    /**
     * Gets coverage of indicators (what they detect).
     *
     * @return Map of indicators to the objects they indicate
     */
    public Map<Indicator, Set<BundleableObject>> getIndicatorCoverage() {
        logger.debug("Calculating indicator coverage");

        Map<Indicator, Set<BundleableObject>> coverage = new HashMap<>();
        List<Indicator> indicators = stixGraph.getObjectsByType(Indicator.class);

        for (Indicator indicator : indicators) {
            Set<BundleableObject> indicated = traversal.findByRelationshipType(
                indicator.getId(), "indicates");

            if (!indicated.isEmpty()) {
                coverage.put(indicator, indicated);
            }
        }

        logger.info("Calculated coverage for {} indicators", coverage.size());
        return coverage;
    }

    /**
     * Finds potential victims of a malware.
     *
     * @param malwareId The malware ID
     * @return Set of potential victim identities
     */
    public Set<Identity> findPotentialVictims(String malwareId) {
        logger.debug("Finding potential victims of malware: {}", malwareId);

        BundleableObject malware = stixGraph.getObject(malwareId);
        if (!(malware instanceof Malware)) {
            return Collections.emptySet();
        }

        Set<Identity> victims = new HashSet<>();

        // Direct targets
        Set<BundleableObject> targets = traversal.findByRelationshipType(
            malwareId, "targets");
        victims.addAll(targets.stream()
            .filter(obj -> obj instanceof Identity)
            .map(obj -> (Identity) obj)
            .collect(Collectors.toSet()));

        // Victims through campaigns
        Set<BundleableObject> campaigns = traversal.getUpstream(malwareId);
        for (BundleableObject campaign : campaigns) {
            if (campaign instanceof Campaign) {
                Set<BundleableObject> campaignTargets = traversal.findByRelationshipType(
                    campaign.getId(), "targets");
                victims.addAll(campaignTargets.stream()
                    .filter(obj -> obj instanceof Identity)
                    .map(obj -> (Identity) obj)
                    .collect(Collectors.toSet()));
            }
        }

        logger.info("Found {} potential victims for malware {}", victims.size(), malwareId);
        return victims;
    }

    /**
     * Finds vulnerabilities exploited by a threat actor.
     *
     * @param threatActorId The threat actor ID
     * @return Set of exploited vulnerabilities
     */
    public Set<Vulnerability> findExploitedVulnerabilities(String threatActorId) {
        logger.debug("Finding vulnerabilities exploited by: {}", threatActorId);

        Set<Vulnerability> vulnerabilities = new HashSet<>();

        // Direct targets
        Set<BundleableObject> targets = traversal.findByRelationshipType(
            threatActorId, "targets");
        vulnerabilities.addAll(targets.stream()
            .filter(obj -> obj instanceof Vulnerability)
            .map(obj -> (Vulnerability) obj)
            .collect(Collectors.toSet()));

        // Through attack patterns
        Set<BundleableObject> attackPatterns = traversal.findByRelationshipType(
            threatActorId, "uses");
        for (BundleableObject pattern : attackPatterns) {
            if (pattern instanceof AttackPattern) {
                Set<BundleableObject> patternTargets = traversal.findByRelationshipType(
                    pattern.getId(), "targets");
                vulnerabilities.addAll(patternTargets.stream()
                    .filter(obj -> obj instanceof Vulnerability)
                    .map(obj -> (Vulnerability) obj)
                    .collect(Collectors.toSet()));
            }
        }

        logger.info("Found {} exploited vulnerabilities", vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Analyzes a kill chain (sequence of steps in an attack).
     *
     * @param campaignId The campaign ID to analyze
     * @return Ordered list of kill chain phases
     */
    public List<BundleableObject> analyzeKillChain(String campaignId) {
        logger.debug("Analyzing kill chain for campaign: {}", campaignId);

        BundleableObject campaign = stixGraph.getObject(campaignId);
        if (!(campaign instanceof Campaign)) {
            return Collections.emptyList();
        }

        List<BundleableObject> killChain = new ArrayList<>();

        // Get all objects used in the campaign
        Set<BundleableObject> used = traversal.findByRelationshipType(campaignId, "uses");

        // Sort by typical kill chain order
        // 1. Reconnaissance (usually no direct objects)
        // 2. Weaponization (Malware, Tool)
        // 3. Delivery (Infrastructure)
        // 4. Exploitation (Vulnerability, AttackPattern)
        // 5. Installation (Malware)
        // 6. Command & Control (Infrastructure)
        // 7. Actions on Objectives (various)

        // Add attack patterns first (exploitation)
        killChain.addAll(used.stream()
            .filter(obj -> obj instanceof AttackPattern)
            .collect(Collectors.toList()));

        // Add vulnerabilities
        killChain.addAll(used.stream()
            .filter(obj -> obj instanceof Vulnerability)
            .collect(Collectors.toList()));

        // Add malware and tools
        killChain.addAll(used.stream()
            .filter(obj -> obj instanceof Malware || obj instanceof Tool)
            .collect(Collectors.toList()));

        // Add infrastructure
        killChain.addAll(used.stream()
            .filter(obj -> obj instanceof Infrastructure)
            .collect(Collectors.toList()));

        logger.info("Analyzed kill chain with {} phases", killChain.size());
        return killChain;
    }

    /**
     * Calculates threat actor sophistication based on their TTPs.
     *
     * @param actorId The threat actor ID
     * @return Sophistication score (0-100)
     */
    public int calculateThreatActorSophistication(String actorId) {
        logger.debug("Calculating sophistication for threat actor: {}", actorId);

        BundleableObject actor = stixGraph.getObject(actorId);
        if (!(actor instanceof ThreatActor)) {
            return 0;
        }

        int score = 0;

        // More attack patterns = higher sophistication
        Set<BundleableObject> attackPatterns = traversal.findByRelationshipType(
            actorId, "uses").stream()
            .filter(obj -> obj instanceof AttackPattern)
            .collect(Collectors.toSet());
        score += Math.min(attackPatterns.size() * 5, 30);

        // Custom malware = higher sophistication
        Set<BundleableObject> malware = traversal.findByRelationshipType(
            actorId, "uses").stream()
            .filter(obj -> obj instanceof Malware)
            .collect(Collectors.toSet());
        score += Math.min(malware.size() * 10, 30);

        // Multiple campaigns = higher sophistication
        Set<BundleableObject> campaigns = traversal.findByRelationshipType(
            actorId, "attributed-to");
        score += Math.min(campaigns.size() * 10, 20);

        // Infrastructure diversity
        Set<BundleableObject> infrastructure = getThreatActorInfrastructure(actorId);
        score += Math.min(infrastructure.size() * 2, 20);

        logger.info("Threat actor {} sophistication score: {}/100", actorId, score);
        return Math.min(score, 100);
    }

    /**
     * Finds common tactics between threat actors.
     *
     * @param actorId1 First threat actor ID
     * @param actorId2 Second threat actor ID
     * @return Set of common attack patterns/tools/malware
     */
    public Set<BundleableObject> findCommonTactics(String actorId1, String actorId2) {
        logger.debug("Finding common tactics between {} and {}", actorId1, actorId2);

        Set<BundleableObject> tactics1 = traversal.findByRelationshipType(actorId1, "uses");
        Set<BundleableObject> tactics2 = traversal.findByRelationshipType(actorId2, "uses");

        Set<BundleableObject> common = new HashSet<>(tactics1);
        common.retainAll(tactics2);

        logger.info("Found {} common tactics", common.size());
        return common;
    }

    /**
     * Generates a threat profile summary for an organization.
     *
     * @param identityId The organization identity ID
     * @return Map containing threat profile information
     */
    public Map<String, Object> generateThreatProfile(String identityId) {
        logger.debug("Generating threat profile for: {}", identityId);

        Map<String, Object> profile = new HashMap<>();

        BundleableObject identity = stixGraph.getObject(identityId);
        if (!(identity instanceof Identity)) {
            return profile;
        }

        // Find threats targeting this identity
        Set<BundleableObject> threats = traversal.getUpstream(identityId).stream()
            .filter(obj -> graph.edgesOf(obj).stream()
                .anyMatch(e -> e.getRelationshipType().equals("targets")))
            .collect(Collectors.toSet());

        // Categorize threats
        List<ThreatActor> threatActors = threats.stream()
            .filter(obj -> obj instanceof ThreatActor)
            .map(obj -> (ThreatActor) obj)
            .collect(Collectors.toList());

        List<Campaign> campaigns = threats.stream()
            .filter(obj -> obj instanceof Campaign)
            .map(obj -> (Campaign) obj)
            .collect(Collectors.toList());

        List<Malware> malware = threats.stream()
            .filter(obj -> obj instanceof Malware)
            .map(obj -> (Malware) obj)
            .collect(Collectors.toList());

        profile.put("identity", identity);
        profile.put("threatActors", threatActors);
        profile.put("campaigns", campaigns);
        profile.put("malware", malware);
        profile.put("threatCount", threats.size());
        profile.put("riskLevel", calculateRiskLevel(threats.size()));

        logger.info("Generated threat profile with {} threats", threats.size());
        return profile;
    }

    /**
     * Calculates risk level based on threat count.
     *
     * @param threatCount Number of threats
     * @return Risk level string
     */
    private String calculateRiskLevel(int threatCount) {
        if (threatCount == 0) return "Low";
        if (threatCount <= 2) return "Medium";
        if (threatCount <= 5) return "High";
        return "Critical";
    }
}