package security.whisper.javastix.vocabulary.vocabularies;

import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RelationshipTypes implements StixVocabulary {

    // STIX Domain Object (SDO) Relationship Types
    private static final Set<String> sdoTerms = new HashSet<>(Arrays.asList(
                "targets",
                "uses",
                "attributed-to",
                "mitigates",
                "indicates",
                "variant-of",
                "impersonates",
                "compromises",
                "originates-from",
                "investigates",
                "remediates",
                "located-at",
                "consists-of",
                "controls",
                "belongs-to",
                "beacons-to",
                "exfiltrates-to",
                "downloads",
                "drops",
                "exploits",
                "characterizes",
                "analysis-of",
                "static-analysis-of",
                "dynamic-analysis-of",
                "authored-by",
                "operates-on",
                "has",
                "based-on",
                "communicates-with",
                "delivers",
                "hosts",
                "prevents",
                "similar",
                "owns",
                "leverages"));

    // Cyber Observable Object (SCO) Relationship Types
    private static final Set<String> cooTerms = new HashSet<>(Arrays.asList(
                "resolves-to",
                "contains"));

    private static final Set<String> commonTerms = new HashSet<>(Arrays.asList(
                "duplicate-of",
                "derived-from",
                "related-to"));

    @Override
    public Set<String> getAllTerms() {
        return Stream.of(sdoTerms.stream(), cooTerms.stream(), commonTerms.stream())
                .flatMap(s -> s)
                .collect(Collectors.toCollection(HashSet::new));
    }

    @Override
    public Set<String> getAllTermsWithAdditional(String[] terms) {
        return Stream.concat(getAllTerms().stream(), Arrays.stream(terms))
                .collect(Collectors.toCollection(HashSet::new));
    }
}
