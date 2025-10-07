package security.whisper.javastix.graph.traversal;

import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.traverse.BreadthFirstIterator;
import org.jgrapht.traverse.DepthFirstIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.graph.StixGraph;
import security.whisper.javastix.graph.StixRelationship;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Provides graph traversal algorithms for STIX graphs.
 * Includes path finding, traversal methods, and relationship chain analysis.
 *
 * @since 1.3.0
 */
public class StixGraphTraversal {

    private static final Logger logger = LoggerFactory.getLogger(StixGraphTraversal.class);

    private final StixGraph stixGraph;
    private final Graph<BundleableObject, StixRelationship> graph;

    /**
     * Creates a new traversal instance for the given STIX graph.
     *
     * @param stixGraph The STIX graph to traverse
     */
    public StixGraphTraversal(StixGraph stixGraph) {
        this.stixGraph = Objects.requireNonNull(stixGraph, "StixGraph cannot be null");
        this.graph = stixGraph.getGraph();
    }

    /**
     * Finds the shortest path between two objects.
     *
     * @param sourceId The ID of the source object
     * @param targetId The ID of the target object
     * @return List of objects in the shortest path, or empty if no path exists
     */
    public List<BundleableObject> findShortestPath(String sourceId, String targetId) {
        BundleableObject source = stixGraph.getObject(sourceId);
        BundleableObject target = stixGraph.getObject(targetId);

        if (source == null || target == null) {
            logger.warn("Cannot find path - source or target not found");
            return Collections.emptyList();
        }

        logger.debug("Finding shortest path from {} to {}", sourceId, targetId);

        DijkstraShortestPath<BundleableObject, StixRelationship> dijkstra =
            new DijkstraShortestPath<>(graph);

        GraphPath<BundleableObject, StixRelationship> path = dijkstra.getPath(source, target);

        if (path == null) {
            logger.debug("No path found between {} and {}", sourceId, targetId);
            return Collections.emptyList();
        }

        List<BundleableObject> result = path.getVertexList();
        logger.info("Found path of length {} from {} to {}", result.size(), sourceId, targetId);
        return result;
    }

    /**
     * Finds all paths between two objects.
     *
     * @param sourceId The ID of the source object
     * @param targetId The ID of the target object
     * @return List of all paths, each path is a list of objects
     */
    public List<List<BundleableObject>> findAllPaths(String sourceId, String targetId) {
        return findAllPaths(sourceId, targetId, null);
    }

    /**
     * Finds all paths between two objects with a maximum length.
     *
     * @param sourceId The ID of the source object
     * @param targetId The ID of the target object
     * @param maxLength Maximum path length, or null for unlimited
     * @return List of all paths, each path is a list of objects
     */
    public List<List<BundleableObject>> findAllPaths(String sourceId, String targetId, Integer maxLength) {
        BundleableObject source = stixGraph.getObject(sourceId);
        BundleableObject target = stixGraph.getObject(targetId);

        if (source == null || target == null) {
            logger.warn("Cannot find paths - source or target not found");
            return Collections.emptyList();
        }

        logger.debug("Finding all paths from {} to {} (max length: {})",
            sourceId, targetId, maxLength);

        AllDirectedPaths<BundleableObject, StixRelationship> allPaths =
            new AllDirectedPaths<>(graph);

        int limit = maxLength != null ? maxLength : Integer.MAX_VALUE;
        List<GraphPath<BundleableObject, StixRelationship>> paths =
            allPaths.getAllPaths(source, target, true, limit);

        List<List<BundleableObject>> result = paths.stream()
            .map(GraphPath::getVertexList)
            .collect(Collectors.toList());

        logger.info("Found {} paths from {} to {}", result.size(), sourceId, targetId);
        return result;
    }

    /**
     * Finds the relationship path between two objects (edges instead of vertices).
     *
     * @param sourceId The ID of the source object
     * @param targetId The ID of the target object
     * @return List of relationships in the shortest path
     */
    public List<StixRelationship> findRelationshipPath(String sourceId, String targetId) {
        BundleableObject source = stixGraph.getObject(sourceId);
        BundleableObject target = stixGraph.getObject(targetId);

        if (source == null || target == null) {
            return Collections.emptyList();
        }

        DijkstraShortestPath<BundleableObject, StixRelationship> dijkstra =
            new DijkstraShortestPath<>(graph);

        GraphPath<BundleableObject, StixRelationship> path = dijkstra.getPath(source, target);

        if (path == null) {
            return Collections.emptyList();
        }

        return path.getEdgeList();
    }

    /**
     * Performs breadth-first traversal from a starting object.
     *
     * @param startId The ID of the starting object
     * @return List of objects in breadth-first order
     */
    public List<BundleableObject> breadthFirstTraversal(String startId) {
        BundleableObject start = stixGraph.getObject(startId);
        if (start == null) {
            logger.warn("Cannot traverse - start object not found: {}", startId);
            return Collections.emptyList();
        }

        logger.debug("Starting BFS from {}", startId);

        List<BundleableObject> result = new ArrayList<>();
        BreadthFirstIterator<BundleableObject, StixRelationship> iterator =
            new BreadthFirstIterator<>(graph, start);

        while (iterator.hasNext()) {
            result.add(iterator.next());
        }

        logger.debug("BFS visited {} objects", result.size());
        return result;
    }

    /**
     * Performs depth-first traversal from a starting object.
     *
     * @param startId The ID of the starting object
     * @return List of objects in depth-first order
     */
    public List<BundleableObject> depthFirstTraversal(String startId) {
        BundleableObject start = stixGraph.getObject(startId);
        if (start == null) {
            logger.warn("Cannot traverse - start object not found: {}", startId);
            return Collections.emptyList();
        }

        logger.debug("Starting DFS from {}", startId);

        List<BundleableObject> result = new ArrayList<>();
        DepthFirstIterator<BundleableObject, StixRelationship> iterator =
            new DepthFirstIterator<>(graph, start);

        while (iterator.hasNext()) {
            result.add(iterator.next());
        }

        logger.debug("DFS visited {} objects", result.size());
        return result;
    }

    /**
     * Gets all objects reachable from a starting object within a maximum depth.
     *
     * @param startId The ID of the starting object
     * @param maxDepth Maximum depth to traverse
     * @return Set of reachable objects
     */
    public Set<BundleableObject> getReachableObjects(String startId, int maxDepth) {
        BundleableObject start = stixGraph.getObject(startId);
        if (start == null) {
            return Collections.emptySet();
        }

        logger.debug("Finding objects reachable from {} within depth {}", startId, maxDepth);

        Set<BundleableObject> visited = new HashSet<>();
        Queue<Pair<BundleableObject, Integer>> queue = new LinkedList<>();
        queue.offer(new Pair<>(start, 0));
        visited.add(start);

        while (!queue.isEmpty()) {
            Pair<BundleableObject, Integer> current = queue.poll();
            BundleableObject obj = current.first;
            int depth = current.second;

            if (depth < maxDepth) {
                for (StixRelationship edge : graph.outgoingEdgesOf(obj)) {
                    BundleableObject target = graph.getEdgeTarget(edge);
                    if (!visited.contains(target)) {
                        visited.add(target);
                        queue.offer(new Pair<>(target, depth + 1));
                    }
                }
            }
        }

        logger.info("Found {} reachable objects from {} within depth {}",
            visited.size(), startId, maxDepth);
        return visited;
    }

    /**
     * Gets all upstream objects (objects that point to the given object).
     *
     * @param objectId The ID of the object
     * @return Set of upstream objects
     */
    public Set<BundleableObject> getUpstream(String objectId) {
        BundleableObject obj = stixGraph.getObject(objectId);
        if (obj == null) {
            return Collections.emptySet();
        }

        Set<BundleableObject> upstream = new HashSet<>();
        for (StixRelationship edge : graph.incomingEdgesOf(obj)) {
            upstream.add(graph.getEdgeSource(edge));
        }

        logger.debug("Found {} upstream objects for {}", upstream.size(), objectId);
        return upstream;
    }

    /**
     * Gets all downstream objects (objects that this object points to).
     *
     * @param objectId The ID of the object
     * @return Set of downstream objects
     */
    public Set<BundleableObject> getDownstream(String objectId) {
        BundleableObject obj = stixGraph.getObject(objectId);
        if (obj == null) {
            return Collections.emptySet();
        }

        Set<BundleableObject> downstream = new HashSet<>();
        for (StixRelationship edge : graph.outgoingEdgesOf(obj)) {
            downstream.add(graph.getEdgeTarget(edge));
        }

        logger.debug("Found {} downstream objects for {}", downstream.size(), objectId);
        return downstream;
    }

    /**
     * Finds all objects connected by a specific relationship type.
     *
     * @param startId The ID of the starting object
     * @param relationshipType The relationship type to follow
     * @return Set of objects connected by the specified relationship type
     */
    public Set<BundleableObject> findByRelationshipType(String startId, String relationshipType) {
        BundleableObject start = stixGraph.getObject(startId);
        if (start == null) {
            return Collections.emptySet();
        }

        Set<BundleableObject> result = new HashSet<>();
        for (StixRelationship edge : graph.outgoingEdgesOf(start)) {
            if (edge.getRelationshipType().equals(relationshipType)) {
                result.add(graph.getEdgeTarget(edge));
            }
        }

        logger.debug("Found {} objects connected to {} by relationship type '{}'",
            result.size(), startId, relationshipType);
        return result;
    }

    /**
     * Follows a chain of relationship types from a starting object.
     *
     * @param startId The ID of the starting object
     * @param relationshipTypes The sequence of relationship types to follow
     * @return List of objects at the end of the relationship chain
     */
    public List<BundleableObject> followRelationshipChain(String startId, String... relationshipTypes) {
        BundleableObject current = stixGraph.getObject(startId);
        if (current == null || relationshipTypes.length == 0) {
            return Collections.emptyList();
        }

        logger.debug("Following relationship chain from {}: {}",
            startId, Arrays.toString(relationshipTypes));

        Set<BundleableObject> currentSet = new HashSet<>();
        currentSet.add(current);

        for (String relType : relationshipTypes) {
            Set<BundleableObject> nextSet = new HashSet<>();
            for (BundleableObject obj : currentSet) {
                for (StixRelationship edge : graph.outgoingEdgesOf(obj)) {
                    if (edge.getRelationshipType().equals(relType)) {
                        nextSet.add(graph.getEdgeTarget(edge));
                    }
                }
            }
            currentSet = nextSet;
            if (currentSet.isEmpty()) {
                break;
            }
        }

        List<BundleableObject> result = new ArrayList<>(currentSet);
        logger.info("Relationship chain from {} yielded {} objects", startId, result.size());
        return result;
    }

    /**
     * Finds all objects within N hops from a starting object.
     *
     * @param startId The ID of the starting object
     * @param hops Number of hops
     * @param directed If true, only follows outgoing edges
     * @return Set of objects within N hops
     */
    public Set<BundleableObject> findWithinHops(String startId, int hops, boolean directed) {
        BundleableObject start = stixGraph.getObject(startId);
        if (start == null) {
            return Collections.emptySet();
        }

        Set<BundleableObject> visited = new HashSet<>();
        Set<BundleableObject> current = new HashSet<>();
        current.add(start);
        visited.add(start);

        for (int i = 0; i < hops; i++) {
            Set<BundleableObject> next = new HashSet<>();
            for (BundleableObject obj : current) {
                // Add objects from outgoing edges
                for (StixRelationship edge : graph.outgoingEdgesOf(obj)) {
                    BundleableObject target = graph.getEdgeTarget(edge);
                    if (!visited.contains(target)) {
                        next.add(target);
                        visited.add(target);
                    }
                }

                // Add objects from incoming edges if not directed
                if (!directed) {
                    for (StixRelationship edge : graph.incomingEdgesOf(obj)) {
                        BundleableObject source = graph.getEdgeSource(edge);
                        if (!visited.contains(source)) {
                            next.add(source);
                            visited.add(source);
                        }
                    }
                }
            }
            current = next;
        }

        logger.info("Found {} objects within {} hops from {}",
            visited.size(), hops, startId);
        return visited;
    }

    /**
     * Simple pair class for internal use.
     */
    private static class Pair<F, S> {
        final F first;
        final S second;

        Pair(F first, S second) {
            this.first = first;
            this.second = second;
        }
    }
}