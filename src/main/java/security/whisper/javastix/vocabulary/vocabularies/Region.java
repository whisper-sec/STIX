package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Region is an open vocabulary that describes geographical regions.
 * This vocabulary is used by the Location SDO to specify broad geographical areas.
 */
public class Region implements StixVocabulary {

    @JsonProperty("region_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "africa",                 // Africa continent
            "eastern-africa",         // Eastern Africa region
            "middle-africa",          // Middle Africa region
            "northern-africa",        // Northern Africa region
            "southern-africa",        // Southern Africa region
            "western-africa",         // Western Africa region
            "americas",               // Americas (North and South America)
            "caribbean",              // Caribbean region
            "central-america",        // Central America region
            "latin-america-caribbean", // Latin America and Caribbean
            "northern-america",       // Northern America (US, Canada, etc.)
            "south-america",          // South America
            "asia",                   // Asia continent
            "central-asia",           // Central Asia region
            "eastern-asia",           // Eastern Asia region
            "southern-asia",          // Southern Asia region
            "south-eastern-asia",     // South-Eastern Asia region
            "western-asia",           // Western Asia region
            "europe",                 // Europe continent
            "eastern-europe",         // Eastern Europe region
            "northern-europe",        // Northern Europe region
            "southern-europe",        // Southern Europe region
            "western-europe",         // Western Europe region
            "oceania",                // Oceania region
            "australia-new-zealand",  // Australia and New Zealand
            "melanesia",              // Melanesia region
            "micronesia",             // Micronesia region
            "polynesia",              // Polynesia region
            "antarctica"              // Antarctica
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