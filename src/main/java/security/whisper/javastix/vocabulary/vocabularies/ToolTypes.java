package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Tool Types is an open vocabulary that describes the type or classification of tools.
 * This vocabulary is used by the Tool SDO to categorize tools used by threat actors or defenders.
 */
public class ToolTypes implements StixVocabulary {

    @JsonProperty("tool_types_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "denial-of-service",      // Tools used for denial of service attacks
            "exploitation",           // Exploitation frameworks and tools
            "information-gathering",  // Reconnaissance and information gathering tools
            "network-capture",        // Network traffic capture tools
            "credential-exploitation", // Tools for exploiting credentials
            "remote-access",          // Remote access tools (RATs)
            "vulnerability-scanning"  // Vulnerability scanning tools
    ));

    @Override
    public Set<String> getAllTerms() {
        return terms;
    }

    @Override
    public Set<String> getAllTermsWithAdditional(String[] terms) {
        return Stream.concat(getAllTerms().stream(), Arrays.stream(terms))
                .collect(Collectors.toCollection(HashSet::new));
    }
}