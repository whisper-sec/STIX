package security.whisper.javastix.graph;

import org.jgrapht.Graph;
import org.jgrapht.graph.DirectedMultigraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.graph.elements.Edge;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.graph.elements.Node;
import security.whisper.javastix.sro.objects.RelationshipSro;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Main graph wrapper for STIX bundles using JGraphT.
 * Provides graph construction, traversal, and analysis capabilities.
 *
 * @since 1.3.0
 */
public class StixGraph {

    private static final Logger logger = LoggerFactory.getLogger(StixGraph.class);

    private final DirectedMultigraph<BundleableObject, StixRelationship> graph;
    private final Map<String, BundleableObject> objectIndex;
    private final BundleObject sourceBundle;

    /**
     * Private constructor - use factory methods to create instances.
     */
    private StixGraph(BundleObject bundle) {
        this.sourceBundle = bundle;
        this.graph = new DirectedMultigraph<>(StixRelationship.class);
        this.objectIndex = new HashMap<>();
        buildGraph(bundle);
    }

    /**
     * Creates a StixGraph from a STIX Bundle.
     *
     * @param bundle The STIX bundle to convert to a graph
     * @return A new StixGraph instance
     */
    public static StixGraph fromBundle(BundleObject bundle) {
        if (bundle == null) {
            throw new IllegalArgumentException("Bundle cannot be null");
        }

        logger.info("Building StixGraph from bundle with {} objects",
            bundle.getObjects().size());

        return new StixGraph(bundle);
    }

    /**
     * Builds the graph from bundle objects and relationships.
     */
    private void buildGraph(BundleObject bundle) {
        // First pass: Add all objects as vertices
        for (BundleableObject obj : bundle.getObjects()) {
            graph.addVertex(obj);
            objectIndex.put(obj.getId(), obj);
            logger.debug("Added vertex: {} ({})", obj.getId(), obj.getType());
        }

        // Second pass: Add relationships as edges
        int relationshipCount = 0;
        for (BundleableObject obj : bundle.getObjects()) {
            if (obj instanceof RelationshipSro) {
                RelationshipSro rel = (RelationshipSro) obj;

                BundleableObject source = objectIndex.get(rel.getSourceRef().getId());
                BundleableObject target = objectIndex.get(rel.getTargetRef().getId());

                if (source != null && target != null) {
                    StixRelationship edge = new StixRelationship(rel);
                    graph.addEdge(source, target, edge);
                    relationshipCount++;
                    logger.debug("Added edge: {} -[{}]-> {}",
                        source.getId(), rel.getRelationshipType(), target.getId());
                } else {
                    logger.warn("Skipping relationship {} - source or target not found in bundle",
                        rel.getId());
                }
            }
        }

        logger.info("Graph built with {} vertices and {} edges",
            graph.vertexSet().size(), relationshipCount);
    }

    /**
     * Gets the underlying JGraphT graph for advanced operations.
     *
     * @return The JGraphT DirectedMultigraph
     */
    public Graph<BundleableObject, StixRelationship> getGraph() {
        return graph;
    }

    /**
     * Gets an object by its ID.
     *
     * @param id The STIX object ID
     * @return The object or null if not found
     */
    public BundleableObject getObject(String id) {
        return objectIndex.get(id);
    }

    /**
     * Gets all vertices (STIX objects) in the graph.
     *
     * @return Set of all STIX objects
     */
    public Set<BundleableObject> getVertices() {
        return graph.vertexSet();
    }

    /**
     * Gets all edges (relationships) in the graph.
     *
     * @return Set of all relationships
     */
    public Set<StixRelationship> getEdges() {
        return graph.edgeSet();
    }

    /**
     * Gets all objects of a specific type.
     *
     * @param type The class type to filter by
     * @param <T> The type parameter
     * @return List of objects of the specified type
     */
    @SuppressWarnings("unchecked")
    public <T extends BundleableObject> List<T> getObjectsByType(Class<T> type) {
        return graph.vertexSet().stream()
            .filter(type::isInstance)
            .map(obj -> (T) obj)
            .collect(Collectors.toList());
    }

    /**
     * Gets all outgoing edges from a vertex.
     *
     * @param objectId The ID of the source object
     * @return Set of outgoing relationships
     */
    public Set<StixRelationship> getOutgoingEdges(String objectId) {
        BundleableObject obj = objectIndex.get(objectId);
        if (obj == null) {
            return Collections.emptySet();
        }
        return graph.outgoingEdgesOf(obj);
    }

    /**
     * Gets all incoming edges to a vertex.
     *
     * @param objectId The ID of the target object
     * @return Set of incoming relationships
     */
    public Set<StixRelationship> getIncomingEdges(String objectId) {
        BundleableObject obj = objectIndex.get(objectId);
        if (obj == null) {
            return Collections.emptySet();
        }
        return graph.incomingEdgesOf(obj);
    }

    /**
     * Gets all neighbors (directly connected objects) of a vertex.
     *
     * @param objectId The ID of the object
     * @return Set of neighboring objects
     */
    public Set<BundleableObject> getNeighbors(String objectId) {
        BundleableObject obj = objectIndex.get(objectId);
        if (obj == null) {
            return Collections.emptySet();
        }

        Set<BundleableObject> neighbors = new HashSet<>();

        // Add targets of outgoing edges
        for (StixRelationship edge : graph.outgoingEdgesOf(obj)) {
            neighbors.add(graph.getEdgeTarget(edge));
        }

        // Add sources of incoming edges
        for (StixRelationship edge : graph.incomingEdgesOf(obj)) {
            neighbors.add(graph.getEdgeSource(edge));
        }

        return neighbors;
    }

    /**
     * Converts the graph to the legacy GraphElement format for compatibility.
     *
     * @return Set of GraphElement objects (Nodes and Edges)
     */
    public Set<GraphElement> toGraphElements() {
        Set<GraphElement> elements = new HashSet<>();

        // Add nodes
        for (BundleableObject obj : graph.vertexSet()) {
            if (!(obj instanceof RelationshipSro)) {
                Node node = new Node(obj.getId(), obj.getType(), null, obj);
                elements.add(node);
            }
        }

        // Add edges
        for (StixRelationship edge : graph.edgeSet()) {
            BundleableObject source = graph.getEdgeSource(edge);
            BundleableObject target = graph.getEdgeTarget(edge);

            Edge graphEdge = new Edge(
                edge.getId(),
                "relationship",
                source.getId(),
                target.getId(),
                edge.getRelationship()
            );

            elements.add(graphEdge);
        }

        logger.debug("Converted to {} GraphElements", elements.size());
        return elements;
    }

    /**
     * Gets statistics about the graph.
     *
     * @return Map of statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("vertexCount", graph.vertexSet().size());
        stats.put("edgeCount", graph.edgeSet().size());
        stats.put("density", calculateDensity());

        // Count by object type
        Map<String, Long> typeCounts = graph.vertexSet().stream()
            .collect(Collectors.groupingBy(
                BundleableObject::getType,
                Collectors.counting()
            ));
        stats.put("objectTypes", typeCounts);

        // Count by relationship type
        Map<String, Long> relTypeCounts = graph.edgeSet().stream()
            .collect(Collectors.groupingBy(
                StixRelationship::getRelationshipType,
                Collectors.counting()
            ));
        stats.put("relationshipTypes", relTypeCounts);

        return stats;
    }

    /**
     * Calculates the graph density (ratio of actual edges to possible edges).
     *
     * @return The graph density (0.0 to 1.0)
     */
    private double calculateDensity() {
        int vertices = graph.vertexSet().size();
        if (vertices <= 1) {
            return 0.0;
        }
        int edges = graph.edgeSet().size();
        int maxEdges = vertices * (vertices - 1); // For directed graph
        return (double) edges / maxEdges;
    }

    /**
     * Gets the source bundle used to create this graph.
     *
     * @return The original bundle
     */
    public BundleObject getSourceBundle() {
        return sourceBundle;
    }

    /**
     * Checks if the graph contains an object with the given ID.
     *
     * @param objectId The object ID to check
     * @return true if the object exists in the graph
     */
    public boolean containsObject(String objectId) {
        return objectIndex.containsKey(objectId);
    }

    /**
     * Gets the degree (number of edges) of a vertex.
     *
     * @param objectId The object ID
     * @return The degree, or -1 if object not found
     */
    public int getDegree(String objectId) {
        BundleableObject obj = objectIndex.get(objectId);
        if (obj == null) {
            return -1;
        }
        return graph.degreeOf(obj);
    }

    /**
     * Gets the in-degree (number of incoming edges) of a vertex.
     *
     * @param objectId The object ID
     * @return The in-degree, or -1 if object not found
     */
    public int getInDegree(String objectId) {
        BundleableObject obj = objectIndex.get(objectId);
        if (obj == null) {
            return -1;
        }
        return graph.inDegreeOf(obj);
    }

    /**
     * Gets the out-degree (number of outgoing edges) of a vertex.
     *
     * @param objectId The object ID
     * @return The out-degree, or -1 if object not found
     */
    public int getOutDegree(String objectId) {
        BundleableObject obj = objectIndex.get(objectId);
        if (obj == null) {
            return -1;
        }
        return graph.outDegreeOf(obj);
    }
}