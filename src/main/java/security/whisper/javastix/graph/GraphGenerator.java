package security.whisper.javastix.graph;

import security.whisper.javastix.graph.elements.GraphElement;

import java.util.Set;

public interface GraphGenerator {

    Set<GraphElement> process();
}
