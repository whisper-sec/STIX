package com.noctisnet.stix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.noctisnet.stix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Infrastructure Type is an open vocabulary used to describe the type of infrastructure.
 * These values are derived from the STIX 2.1 specification.
 */
public class InfrastructureTypes implements StixVocabulary {

    @JsonProperty("infrastructure_types_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "amplification",
            "anonymization",
            "botnet",
            "command-and-control",
            "control-system",
            "dns",
            "domain-registration",
            "exfiltration",
            "firewall",
            "hosting-service",
            "isp",
            "network",
            "phishing",
            "proxy",
            "staging",
            "workstation"
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
