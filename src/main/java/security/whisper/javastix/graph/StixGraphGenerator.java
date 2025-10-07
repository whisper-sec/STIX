package security.whisper.javastix.graph;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.graph.bundle.BundleObjectGraphGenerator;
import security.whisper.javastix.graph.elements.GraphElement;
import security.whisper.javastix.json.StixParsers;

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
