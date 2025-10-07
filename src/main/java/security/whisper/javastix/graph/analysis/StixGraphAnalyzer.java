package security.whisper.javastix.graph.analysis;

import org.jgrapht.Graph;
import org.jgrapht.alg.connectivity.ConnectivityInspector;
import org.jgrapht.alg.connectivity.KosarajuStrongConnectivityInspector;
import org.jgrapht.alg.cycle.CycleDetector;
import org.jgrapht.alg.cycle.JohnsonSimpleCycles;
import org.jgrapht.alg.scoring.BetweennessCentrality;
import org.jgrapht.alg.scoring.ClosenessCentrality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.graph.StixGraph;
import security.whisper.javastix.graph.StixRelationship;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Provides graph analysis capabilities for STIX graphs.
 * Includes centrality metrics, component analysis, and cycle detection.
 *
 * @since 1.3.0
 */
public class StixGraphAnalyzer {

    private static final Logger logger = LoggerFactory.getLogger(StixGraphAnalyzer.class);

    private final StixGraph stixGraph;
    private final Graph<BundleableObject, StixRelationship> graph;

    /**
     * Creates a new analyzer for the given STIX graph.
     *
     * @param stixGraph The STIX graph to analyze
     */
    public StixGraphAnalyzer(StixGraph stixGraph) {
        this.stixGraph = Objects.requireNonNull(stixGraph, "StixGraph cannot be null");
        this.graph = stixGraph.getGraph();
    }

    /**
     * Calculates degree centrality for all vertices.
     * Degree centrality is the number of edges connected to a vertex.
     *
     * @return Map of objects to their degree centrality scores
     */
    public Map<BundleableObject, Double> calculateDegreeCentrality() {
        logger.debug("Calculating degree centrality");

        Map<BundleableObject, Double> centrality = new HashMap<>();
        int maxDegree = 0;

        // Calculate raw degrees
        for (BundleableObject vertex : graph.vertexSet()) {
            int degree = graph.degreeOf(vertex);
            if (degree > maxDegree) {
                maxDegree = degree;
            }
            centrality.put(vertex, (double) degree);
        }

        // Normalize if there are edges
        if (maxDegree > 0) {
            final int max = maxDegree;
            centrality.replaceAll((k, v) -> v / max);
        }

        logger.info("Calculated degree centrality for {} vertices", centrality.size());
        return centrality;
    }

    /**
     * Calculates betweenness centrality for all vertices.
     * Betweenness centrality measures how often a vertex appears on shortest paths.
     *
     * @return Map of objects to their betweenness centrality scores
     */
    public Map<BundleableObject, Double> calculateBetweennessCentrality() {
        logger.debug("Calculating betweenness centrality");

        BetweennessCentrality<BundleableObject, StixRelationship> bc =
            new BetweennessCentrality<>(graph, true);

        Map<BundleableObject, Double> scores = bc.getScores();
        logger.info("Calculated betweenness centrality for {} vertices", scores.size());
        return scores;
    }

    /**
     * Calculates closeness centrality for all vertices.
     * Closeness centrality measures average distance to all other vertices.
     *
     * @return Map of objects to their closeness centrality scores
     */
    public Map<BundleableObject, Double> calculateClosenessCentrality() {
        logger.debug("Calculating closeness centrality");

        ClosenessCentrality<BundleableObject, StixRelationship> cc =
            new ClosenessCentrality<>(graph);

        Map<BundleableObject, Double> scores = cc.getScores();
        logger.info("Calculated closeness centrality for {} vertices", scores.size());
        return scores;
    }

    /**
     * Finds the most connected objects (hubs) in the graph.
     *
     * @param topN Number of top hubs to return
     * @return List of the most connected objects, sorted by degree
     */
    public List<BundleableObject> findHubs(int topN) {
        logger.debug("Finding top {} hubs", topN);

        Map<BundleableObject, Integer> degrees = new HashMap<>();
        for (BundleableObject vertex : graph.vertexSet()) {
            degrees.put(vertex, graph.degreeOf(vertex));
        }

        List<BundleableObject> hubs = degrees.entrySet().stream()
            .sorted(Map.Entry.<BundleableObject, Integer>comparingByValue().reversed())
            .limit(topN)
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());

        logger.info("Found {} hubs (top connected objects)", hubs.size());
        return hubs;
    }

    /**
     * Finds all connected components in the graph.
     * A connected component is a maximal set of connected vertices.
     *
     * @return List of connected components, each as a set of objects
     */
    public List<Set<BundleableObject>> findConnectedComponents() {
        logger.debug("Finding connected components");

        ConnectivityInspector<BundleableObject, StixRelationship> inspector =
            new ConnectivityInspector<>(graph);

        List<Set<BundleableObject>> components = inspector.connectedSets();
        logger.info("Found {} connected components", components.size());
        return components;
    }

    /**
     * Finds all strongly connected components in the directed graph.
     * In a strongly connected component, every vertex is reachable from every other vertex.
     *
     * @return List of strongly connected components
     */
    public List<Set<BundleableObject>> findStronglyConnectedComponents() {
        logger.debug("Finding strongly connected components");

        KosarajuStrongConnectivityInspector<BundleableObject, StixRelationship> inspector =
            new KosarajuStrongConnectivityInspector<>(graph);

        List<Set<BundleableObject>> components = inspector.stronglyConnectedSets();
        logger.info("Found {} strongly connected components", components.size());
        return components;
    }

    /**
     * Finds all isolated objects (vertices with no edges).
     *
     * @return Set of isolated objects
     */
    public Set<BundleableObject> findIsolatedObjects() {
        logger.debug("Finding isolated objects");

        Set<BundleableObject> isolated = graph.vertexSet().stream()
            .filter(v -> graph.degreeOf(v) == 0)
            .collect(Collectors.toSet());

        logger.info("Found {} isolated objects", isolated.size());
        return isolated;
    }

    /**
     * Checks if the graph contains any cycles.
     *
     * @return true if the graph has cycles, false otherwise
     */
    public boolean hasCycles() {
        logger.debug("Checking for cycles");

        CycleDetector<BundleableObject, StixRelationship> detector =
            new CycleDetector<>(graph);

        boolean hasCycles = detector.detectCycles();
        logger.info("Graph {} cycles", hasCycles ? "contains" : "does not contain");
        return hasCycles;
    }

    /**
     * Finds all simple cycles in the graph.
     * A simple cycle is a closed path with no repeated vertices except the first/last.
     *
     * @return List of cycles, each as a list of objects
     */
    public List<List<BundleableObject>> findAllCycles() {
        logger.debug("Finding all cycles");

        JohnsonSimpleCycles<BundleableObject, StixRelationship> cyclesFinder =
            new JohnsonSimpleCycles<>(graph);

        List<List<BundleableObject>> cycles = cyclesFinder.findSimpleCycles();
        logger.info("Found {} cycles", cycles.size());
        return cycles;
    }

    /**
     * Gets the distribution of object types in the graph.
     *
     * @return Map of object type to count
     */
    public Map<String, Integer> getObjectTypeDistribution() {
        Map<String, Integer> distribution = new HashMap<>();

        for (BundleableObject obj : graph.vertexSet()) {
            String type = obj.getType();
            distribution.merge(type, 1, Integer::sum);
        }

        logger.debug("Object type distribution: {}", distribution);
        return distribution;
    }

    /**
     * Gets the distribution of relationship types in the graph.
     *
     * @return Map of relationship type to count
     */
    public Map<String, Integer> getRelationshipTypeDistribution() {
        Map<String, Integer> distribution = new HashMap<>();

        for (StixRelationship rel : graph.edgeSet()) {
            String type = rel.getRelationshipType();
            distribution.merge(type, 1, Integer::sum);
        }

        logger.debug("Relationship type distribution: {}", distribution);
        return distribution;
    }

    /**
     * Analyzes the graph structure and returns comprehensive metrics.
     *
     * @return Map containing various graph metrics
     */
    public Map<String, Object> analyzeGraphStructure() {
        logger.info("Analyzing graph structure");

        Map<String, Object> analysis = new HashMap<>();

        // Basic metrics
        analysis.put("vertexCount", graph.vertexSet().size());
        analysis.put("edgeCount", graph.edgeSet().size());
        analysis.put("density", calculateDensity());

        // Component analysis
        List<Set<BundleableObject>> components = findConnectedComponents();
        analysis.put("componentCount", components.size());
        analysis.put("largestComponentSize",
            components.stream().mapToInt(Set::size).max().orElse(0));

        // Isolated objects
        analysis.put("isolatedObjectCount", findIsolatedObjects().size());

        // Cycles
        analysis.put("hasCycles", hasCycles());

        // Degree statistics
        IntSummaryStatistics degreeStats = graph.vertexSet().stream()
            .mapToInt(graph::degreeOf)
            .summaryStatistics();
        analysis.put("avgDegree", degreeStats.getAverage());
        analysis.put("maxDegree", degreeStats.getMax());
        analysis.put("minDegree", degreeStats.getMin());

        // Type distributions
        analysis.put("objectTypes", getObjectTypeDistribution());
        analysis.put("relationshipTypes", getRelationshipTypeDistribution());

        logger.info("Graph analysis complete");
        return analysis;
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
     * Finds objects that appear in cycles.
     *
     * @return Set of objects that are part of at least one cycle
     */
    public Set<BundleableObject> findObjectsInCycles() {
        logger.debug("Finding objects in cycles");

        CycleDetector<BundleableObject, StixRelationship> detector =
            new CycleDetector<>(graph);

        Set<BundleableObject> inCycles = detector.findCycles();
        logger.info("Found {} objects in cycles", inCycles.size());
        return inCycles;
    }

    /**
     * Calculates the average path length in the graph.
     *
     * @return Average path length, or -1 if graph is not connected
     */
    public double calculateAveragePathLength() {
        logger.debug("Calculating average path length");

        ClosenessCentrality<BundleableObject, StixRelationship> cc =
            new ClosenessCentrality<>(graph);

        // The closeness centrality algorithm internally calculates all shortest paths
        // We can use this to derive average path length
        double sum = 0;
        int count = 0;

        for (BundleableObject v : graph.vertexSet()) {
            Double score = cc.getScores().get(v);
            if (score != null && score > 0) {
                // Closeness is 1/avg_distance, so avg_distance = 1/closeness
                sum += 1.0 / score;
                count++;
            }
        }

        double avgPathLength = count > 0 ? sum / count : -1;
        logger.info("Average path length: {}", avgPathLength);
        return avgPathLength;
    }

    /**
     * Finds articulation points (vertices whose removal increases component count).
     *
     * @return Set of articulation points
     */
    public Set<BundleableObject> findArticulationPoints() {
        logger.debug("Finding articulation points");

        ConnectivityInspector<BundleableObject, StixRelationship> inspector =
            new ConnectivityInspector<>(graph);

        int originalComponents = inspector.connectedSets().size();
        Set<BundleableObject> articulationPoints = new HashSet<>();

        for (BundleableObject vertex : graph.vertexSet()) {
            // Skip isolated vertices
            if (graph.degreeOf(vertex) == 0) {
                continue;
            }

            // Temporarily remove vertex and check connectivity
            Set<StixRelationship> removedEdges = new HashSet<>();
            removedEdges.addAll(graph.edgesOf(vertex));

            graph.removeVertex(vertex);
            ConnectivityInspector<BundleableObject, StixRelationship> tempInspector =
                new ConnectivityInspector<>(graph);

            if (tempInspector.connectedSets().size() > originalComponents) {
                articulationPoints.add(vertex);
            }

            // Restore vertex and edges
            graph.addVertex(vertex);
            for (StixRelationship edge : removedEdges) {
                BundleableObject source = edge.getRelationship().getSourceRef();
                BundleableObject target = edge.getRelationship().getTargetRef();
                if (graph.containsVertex(source) && graph.containsVertex(target)) {
                    graph.addEdge(source, target, edge);
                }
            }
        }

        logger.info("Found {} articulation points", articulationPoints.size());
        return articulationPoints;
    }
}