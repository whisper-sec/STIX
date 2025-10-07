package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Pattern Type is an open vocabulary that describes the pattern language used in an indicator pattern.
 * This vocabulary is used by the Indicator SDO's pattern_type property.
 * The default value is "stix" for STIX patterning language.
 */
public class PatternType implements StixVocabulary {

    @JsonProperty("pattern_type_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "stix",      // The default STIX patterning language
            "snort",     // Snort rules
            "yara",      // YARA rules
            "sigma",     // Sigma rules
            "suricata",  // Suricata rules
            "pcre"       // Perl Compatible Regular Expressions
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