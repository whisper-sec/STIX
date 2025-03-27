package com.noctisnet.stix.graph;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.noctisnet.stix.bundle.BundleObject;
import com.noctisnet.stix.graph.bundle.BundleObjectGraphGenerator;
import com.noctisnet.stix.graph.elements.GraphElement;
import com.noctisnet.stix.json.StixParsers;

import java.util.HashSet;
import java.util.Set;

public class StixGraphGenerator implements GraphGenerator {

    private final BundleObject bundle;
    private final ObjectMapper jsonMapper = StixParsers.getJsonMapper();

    public StixGraphGenerator(BundleObject bundle) {
        this.bundle = bundle;
    }

    @Override
    public Set<GraphElement> process(){
        Set<GraphElement> elements = new HashSet<>();

        elements.addAll(new BundleObjectGraphGenerator(bundle).process());

        return elements;
    }

    public String toJson(){
        try {
            return jsonMapper.writeValueAsString(process());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
