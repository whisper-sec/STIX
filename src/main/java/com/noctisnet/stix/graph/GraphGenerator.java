package com.noctisnet.stix.graph;

import com.noctisnet.stix.graph.elements.GraphElement;

import java.util.Set;

public interface GraphGenerator {

    Set<GraphElement> process();
}
