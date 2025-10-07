package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Threat Actor Types is an open vocabulary that describes different types of threat actors.
 * This vocabulary is used by the Threat Actor SDO to categorize threat actors.
 */
public class ThreatActorTypes implements StixVocabulary {

    @JsonProperty("threat_actor_types_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "activist",           // Hacktivist or activist groups
            "competitor",         // Competitor organizations
            "crime-syndicate",    // Organized crime syndicates
            "criminal",           // Individual criminals or criminal groups
            "hacker",             // Individual hackers or hacker groups
            "insider-accidental", // Accidental insider threats
            "insider-disgruntled", // Disgruntled insider threats
            "nation-state",       // Nation-state actors
            "sensationalist",     // Actors seeking attention/notoriety
            "spy",                // Espionage-focused actors
            "terrorist",          // Terrorist organizations
            "unknown"             // Unknown threat actor type
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