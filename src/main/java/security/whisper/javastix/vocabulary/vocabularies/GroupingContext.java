package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Grouping Context is an open vocabulary used to describe the context of a grouping of STIX objects.
 * These values are derived from the STIX 2.1 specification.
 */
public class GroupingContext implements StixVocabulary {

    @JsonProperty("grouping_context_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "suspicious-activity",
            "malware-analysis",
            "unspecified"
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