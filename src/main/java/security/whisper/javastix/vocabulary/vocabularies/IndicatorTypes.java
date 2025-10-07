package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Indicator Type is an open vocabulary used to categorize indicators.
 * These values are derived from the STIX 2.1 specification.
 */
public class IndicatorTypes implements StixVocabulary {

    @JsonProperty("indicator_types_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "anomalous-activity",
            "anonymization",
            "benign",
            "compromised",
            "malicious-activity",
            "attribution",
            "unknown"
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
