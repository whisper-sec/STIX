package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Report Types is an open vocabulary that describes the primary purpose or subject of a report.
 * This vocabulary is used by the Report SDO to categorize reports.
 */
public class ReportTypes implements StixVocabulary {

    @JsonProperty("report_types_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "attack-pattern",     // Report describes an attack pattern
            "campaign",           // Report describes a campaign
            "identity",           // Report describes an identity
            "indicator",          // Report describes indicators
            "intrusion-set",      // Report describes an intrusion set
            "malware",            // Report describes malware
            "observed-data",      // Report describes observed data
            "threat-actor",       // Report describes a threat actor
            "threat-report",      // General threat report
            "tool",               // Report describes tools
            "vulnerability"       // Report describes vulnerabilities
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