package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Opinion Enum is an enumeration that captures different levels of agreement or disagreement.
 * These values are defined by the STIX 2.1 specification and are fixed (not open).
 */
public class OpinionEnum implements StixVocabulary {

    @JsonProperty("opinion_enum")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "strongly-disagree",
            "disagree",
            "neutral",
            "agree",
            "strongly-agree"
    ));

    @Override
    public Set<String> getAllTerms() {
        return terms;
    }

    @Override
    public Set<String> getAllTermsWithAdditional(String[] terms) {
        // Opinion is a closed vocabulary, so we don't allow additional terms
        return getAllTerms();
    }
}