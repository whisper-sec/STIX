package security.whisper.javastix.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.objects.Relationship;
import security.whisper.javastix.sro.objects.RelationshipSro;
import security.whisper.javastix.sro.objects.Sighting;
import security.whisper.javastix.sro.objects.SightingSro;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Helper class for STIX Relationship operations.
 * Provides utilities for creating, filtering, and analyzing relationships.
 *
 * @since 1.3.0
 */
public class StixRelationshipHelper {

    private static final Logger logger = LoggerFactory.getLogger(StixRelationshipHelper.class);

    /**
     * Common relationship types as defined in STIX 2.1 specification.
     */
    public static final String REL_USES = "uses";
    public static final String REL_TARGETS = "targets";
    public static final String REL_INDICATES = "indicates";
    public static final String REL_MITIGATES = "mitigates";
    public static final String REL_ATTRIBUTED_TO = "attributed-to";
    public static final String REL_DELIVERS = "delivers";
    public static final String REL_DROPS = "drops";
    public static final String REL_EXPLOITS = "exploits";
    public static final String REL_VARIANT_OF = "variant-of";
    public static final String REL_IMPERSONATES = "impersonates";
    public static final String REL_HAS = "has";
    public static final String REL_LOCATED_AT = "located-at";
    public static final String REL_BASED_ON = "based-on";

    /**
     * Private constructor to prevent instantiation.
     */
    private StixRelationshipHelper() {
    }

    /**
     * Creates a simple relationship between two objects.
     *
     * @param source The source object
     * @param relationshipType The relationship type
     * @param target The target object
     * @return A new RelationshipSro
     */
    public static RelationshipSro createRelationship(
            BundleableObject source,
            String relationshipType,
            BundleableObject target) {

        if (source == null || target == null || relationshipType == null) {
            throw new IllegalArgumentException("Source, target, and relationship type cannot be null");
        }

        logger.debug("Creating relationship: {} -[{}]-> {}",
            source.getId(), relationshipType, target.getId());

        return Relationship.builder()
            .sourceRef(source)
            .relationshipType(relationshipType)
            .targetRef(target)
            .build();
    }

    /**
     * Creates a relationship with additional properties.
     *
     * @param source The source object
     * @param relationshipType The relationship type
     * @param target The target object
     * @param confidence Confidence level (0-100)
     * @param description Optional description
     * @return A new RelationshipSro
     */
    public static RelationshipSro createRelationshipWithMetadata(
            BundleableObject source,
            String relationshipType,
            BundleableObject target,
            Integer confidence,
            String description) {

        logger.debug("Creating relationship with metadata: {} -[{}]-> {}",
            source.getId(), relationshipType, target.getId());

        var builder = Relationship.builder()
            .sourceRef(source)
            .relationshipType(relationshipType)
            .targetRef(target);

        // Note: confidence is not a standard field in RelationshipSro
        // It would need to be added as a custom property

        if (description != null) {
            builder.description(description);
        }

        return builder.build();
    }

    /**
     * Filters relationships by type from a bundle.
     *
     * @param bundle The bundle to filter
     * @param relationshipType The relationship type to filter by
     * @return List of relationships of the specified type
     */
    public static List<RelationshipSro> filterByType(BundleObject bundle, String relationshipType) {
        if (bundle == null || relationshipType == null) {
            return Collections.emptyList();
        }

        logger.debug("Filtering relationships by type: {}", relationshipType);

        List<RelationshipSro> filtered = bundle.getObjects().stream()
            .filter(obj -> obj instanceof RelationshipSro)
            .map(obj -> (RelationshipSro) obj)
            .filter(rel -> rel.getRelationshipType().equals(relationshipType))
            .collect(Collectors.toList());

        logger.debug("Found {} relationships of type {}", filtered.size(), relationshipType);
        return filtered;
    }

    /**
     * Finds all relationships where the specified object is the source.
     *
     * @param bundle The bundle to search
     * @param sourceId The ID of the source object
     * @return List of relationships from the source
     */
    public static List<RelationshipSro> findRelationshipsFrom(BundleObject bundle, String sourceId) {
        if (bundle == null || sourceId == null) {
            return Collections.emptyList();
        }

        return bundle.getObjects().stream()
            .filter(obj -> obj instanceof RelationshipSro)
            .map(obj -> (RelationshipSro) obj)
            .filter(rel -> rel.getSourceRef().getId().equals(sourceId))
            .collect(Collectors.toList());
    }

    /**
     * Finds all relationships where the specified object is the target.
     *
     * @param bundle The bundle to search
     * @param targetId The ID of the target object
     * @return List of relationships to the target
     */
    public static List<RelationshipSro> findRelationshipsTo(BundleObject bundle, String targetId) {
        if (bundle == null || targetId == null) {
            return Collections.emptyList();
        }

        return bundle.getObjects().stream()
            .filter(obj -> obj instanceof RelationshipSro)
            .map(obj -> (RelationshipSro) obj)
            .filter(rel -> rel.getTargetRef().getId().equals(targetId))
            .collect(Collectors.toList());
    }

    /**
     * Gets valid relationship types for a given object type according to STIX 2.1 spec.
     *
     * @param objectType The STIX object type
     * @return Set of valid relationship types
     */
    public static Set<String> getValidRelationshipTypes(String objectType) {
        Set<String> validTypes = new HashSet<>();

        switch (objectType) {
            case "attack-pattern":
                validTypes.addAll(Arrays.asList(REL_USES, REL_TARGETS, REL_DELIVERS));
                break;
            case "campaign":
                validTypes.addAll(Arrays.asList(REL_ATTRIBUTED_TO, REL_USES, REL_TARGETS));
                break;
            case "indicator":
                validTypes.addAll(Arrays.asList(REL_INDICATES, REL_BASED_ON));
                break;
            case "malware":
                validTypes.addAll(Arrays.asList(REL_USES, REL_TARGETS, REL_VARIANT_OF,
                    REL_DELIVERS, REL_DROPS));
                break;
            case "threat-actor":
                validTypes.addAll(Arrays.asList(REL_USES, REL_TARGETS, REL_ATTRIBUTED_TO,
                    REL_IMPERSONATES, REL_LOCATED_AT));
                break;
            case "tool":
                validTypes.addAll(Arrays.asList(REL_USES, REL_TARGETS, REL_DELIVERS, REL_DROPS));
                break;
            case "vulnerability":
                validTypes.add(REL_TARGETS);
                break;
            case "identity":
                validTypes.add(REL_LOCATED_AT);
                break;
            case "infrastructure":
                validTypes.addAll(Arrays.asList(REL_USES, REL_HAS, REL_LOCATED_AT));
                break;
            case "course-of-action":
                validTypes.add(REL_MITIGATES);
                break;
        }

        // Common relationships that can apply to many types
        validTypes.add("related-to");
        validTypes.add("derived-from");

        return validTypes;
    }

    /**
     * Validates if a relationship type is valid between two object types.
     *
     * @param sourceType The source object type
     * @param relationshipType The relationship type
     * @param targetType The target object type
     * @return true if valid, false otherwise
     */
    public static boolean isValidRelationship(String sourceType, String relationshipType, String targetType) {
        // Check if the relationship type is valid for the source
        Set<String> validTypes = getValidRelationshipTypes(sourceType);
        if (!validTypes.contains(relationshipType)) {
            return false;
        }

        // Additional validation based on STIX 2.1 specification
        switch (relationshipType) {
            case REL_INDICATES:
                // Indicators can only indicate threat actors, malware, tools, attack patterns, campaigns
                return Arrays.asList("threat-actor", "malware", "tool", "attack-pattern", "campaign")
                    .contains(targetType);
            case REL_MITIGATES:
                // Mitigations target vulnerabilities, malware, attack patterns, tools
                return Arrays.asList("vulnerability", "malware", "attack-pattern", "tool")
                    .contains(targetType);
            case REL_TARGETS:
                // Targets are usually identities, vulnerabilities, or infrastructure
                return Arrays.asList("identity", "vulnerability", "infrastructure", "location")
                    .contains(targetType);
            case REL_USES:
                // Uses relationships typically point to tools, malware, attack patterns, infrastructure
                return Arrays.asList("tool", "malware", "attack-pattern", "infrastructure")
                    .contains(targetType);
            case REL_ATTRIBUTED_TO:
                // Attribution is usually to threat actors or identities
                return Arrays.asList("threat-actor", "identity").contains(targetType);
            default:
                return true; // Allow other relationships by default
        }
    }

    /**
     * Creates a chain of relationships.
     *
     * @param objects The objects to chain
     * @param relationshipTypes The relationship types for each connection
     * @return List of relationships forming the chain
     */
    public static List<RelationshipSro> createRelationshipChain(
            List<BundleableObject> objects,
            List<String> relationshipTypes) {

        if (objects == null || relationshipTypes == null) {
            throw new IllegalArgumentException("Objects and relationship types cannot be null");
        }

        if (objects.size() != relationshipTypes.size() + 1) {
            throw new IllegalArgumentException(
                "Number of relationship types must be one less than number of objects");
        }

        logger.debug("Creating relationship chain with {} objects", objects.size());

        List<RelationshipSro> chain = new ArrayList<>();
        for (int i = 0; i < relationshipTypes.size(); i++) {
            RelationshipSro rel = createRelationship(
                objects.get(i),
                relationshipTypes.get(i),
                objects.get(i + 1)
            );
            chain.add(rel);
        }

        logger.info("Created relationship chain with {} relationships", chain.size());
        return chain;
    }

    /**
     * Inverts a relationship (swaps source and target, adjusts type if needed).
     *
     * @param relationship The relationship to invert
     * @return A new inverted relationship
     */
    public static RelationshipSro invertRelationship(RelationshipSro relationship) {
        if (relationship == null) {
            throw new IllegalArgumentException("Relationship cannot be null");
        }

        String invertedType = invertRelationshipType(relationship.getRelationshipType());

        logger.debug("Inverting relationship: {} becomes {}",
            relationship.getRelationshipType(), invertedType);

        return Relationship.builder()
            .sourceRef(relationship.getTargetRef())
            .relationshipType(invertedType)
            .targetRef(relationship.getSourceRef())
            .description("Inverted: " + relationship.getDescription().orElse(""))
            .build();
    }

    /**
     * Gets the inverse of a relationship type.
     *
     * @param relationshipType The relationship type
     * @return The inverted relationship type
     */
    private static String invertRelationshipType(String relationshipType) {
        switch (relationshipType) {
            case REL_USES:
                return "used-by";
            case REL_TARGETS:
                return "targeted-by";
            case REL_INDICATES:
                return "indicated-by";
            case REL_MITIGATES:
                return "mitigated-by";
            case REL_ATTRIBUTED_TO:
                return "has-attribution";
            case REL_DELIVERS:
                return "delivered-by";
            case REL_DROPS:
                return "dropped-by";
            case REL_EXPLOITS:
                return "exploited-by";
            case REL_VARIANT_OF:
                return "has-variant";
            case REL_IMPERSONATES:
                return "impersonated-by";
            case REL_HAS:
                return "belongs-to";
            case REL_LOCATED_AT:
                return "has-located";
            case REL_BASED_ON:
                return "basis-for";
            case "related-to":
                return "related-to"; // Symmetric
            case "derived-from":
                return "derives";
            default:
                return "inverse-of-" + relationshipType;
        }
    }

    /**
     * Groups relationships by their type.
     *
     * @param relationships List of relationships
     * @return Map of relationship type to list of relationships
     */
    public static Map<String, List<RelationshipSro>> groupByType(List<RelationshipSro> relationships) {
        if (relationships == null) {
            return Collections.emptyMap();
        }

        return relationships.stream()
            .collect(Collectors.groupingBy(RelationshipSro::getRelationshipType));
    }

    /**
     * Filters relationships by confidence level.
     * Note: Standard STIX 2.1 relationships don't have confidence field.
     *
     * @param relationships List of relationships
     * @param minConfidence Minimum confidence level (0-100)
     * @return Empty list (confidence not available in standard relationships)
     */
    public static List<RelationshipSro> filterByConfidence(
            List<RelationshipSro> relationships,
            int minConfidence) {

        if (relationships == null) {
            return Collections.emptyList();
        }

        // Confidence is not a standard field in RelationshipSro
        // Would need to check custom properties for confidence
        return Collections.emptyList();
    }

    /**
     * Finds bidirectional relationships (where A->B and B->A exist).
     *
     * @param bundle The bundle to analyze
     * @return List of bidirectional relationship pairs
     */
    public static List<RelationshipPair> findBidirectionalRelationships(BundleObject bundle) {
        if (bundle == null) {
            return Collections.emptyList();
        }

        List<RelationshipPair> pairs = new ArrayList<>();
        List<RelationshipSro> relationships = bundle.getObjects().stream()
            .filter(obj -> obj instanceof RelationshipSro)
            .map(obj -> (RelationshipSro) obj)
            .collect(Collectors.toList());

        for (int i = 0; i < relationships.size(); i++) {
            RelationshipSro rel1 = relationships.get(i);
            for (int j = i + 1; j < relationships.size(); j++) {
                RelationshipSro rel2 = relationships.get(j);

                // Check if they form a bidirectional pair
                if (rel1.getSourceRef().getId().equals(rel2.getTargetRef().getId()) &&
                    rel1.getTargetRef().getId().equals(rel2.getSourceRef().getId())) {
                    pairs.add(new RelationshipPair(rel1, rel2));
                }
            }
        }

        logger.info("Found {} bidirectional relationship pairs", pairs.size());
        return pairs;
    }

    /**
     * Creates a sighting relationship.
     *
     * @param sightingOf The object that was sighted (must be a DomainObject)
     * @param observedData Optional observed data references
     * @param count Number of times sighted
     * @return A new SightingSro
     */
    public static SightingSro createSighting(
            DomainObject sightingOf,
            List<ObservedDataSdo> observedData,
            Integer count) {

        if (sightingOf == null) {
            throw new IllegalArgumentException("Sighting target cannot be null");
        }

        logger.debug("Creating sighting for: {}", sightingOf.getId());

        var builder = Sighting.builder()
            .sightingOfRef(sightingOf);

        if (observedData != null && !observedData.isEmpty()) {
            builder.addAllObservedDataRefs(observedData);
        }

        if (count != null && count > 0) {
            builder.count(count);
        }

        return builder.build();
    }

    /**
     * Calculates relationship statistics for a bundle.
     *
     * @param bundle The bundle to analyze
     * @return Map of statistics
     */
    public static Map<String, Object> calculateRelationshipStatistics(BundleObject bundle) {
        if (bundle == null) {
            return Collections.emptyMap();
        }

        Map<String, Object> stats = new HashMap<>();

        List<RelationshipSro> relationships = bundle.getObjects().stream()
            .filter(obj -> obj instanceof RelationshipSro)
            .map(obj -> (RelationshipSro) obj)
            .collect(Collectors.toList());

        stats.put("totalRelationships", relationships.size());

        // Group by type
        Map<String, Long> typeCount = relationships.stream()
            .collect(Collectors.groupingBy(
                RelationshipSro::getRelationshipType,
                Collectors.counting()
            ));
        stats.put("relationshipTypes", typeCount);

        // Note: Confidence is not a standard field in RelationshipSro
        // Setting default values for statistics that would involve confidence
        stats.put("averageConfidence", 0.0);
        stats.put("highConfidenceCount", 0L);

        // Most connected objects
        Map<String, Long> sourceCount = relationships.stream()
            .collect(Collectors.groupingBy(
                rel -> rel.getSourceRef().getId(),
                Collectors.counting()
            ));

        String mostActiveSource = sourceCount.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse(null);
        stats.put("mostActiveSource", mostActiveSource);

        logger.debug("Calculated relationship statistics: {}", stats);
        return stats;
    }

    /**
     * Helper class to represent a bidirectional relationship pair.
     */
    public static class RelationshipPair {
        private final RelationshipSro forward;
        private final RelationshipSro backward;

        public RelationshipPair(RelationshipSro forward, RelationshipSro backward) {
            this.forward = forward;
            this.backward = backward;
        }

        public RelationshipSro getForward() {
            return forward;
        }

        public RelationshipSro getBackward() {
            return backward;
        }

        @Override
        public String toString() {
            return String.format("%s <-[%s/%s]-> %s",
                forward.getSourceRef().getId(),
                forward.getRelationshipType(),
                backward.getRelationshipType(),
                forward.getTargetRef().getId());
        }
    }
}