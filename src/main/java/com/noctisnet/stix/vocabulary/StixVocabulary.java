package com.noctisnet.stix.vocabulary;

import java.util.Set;

public interface StixVocabulary {

    /**
     * Get all default terms
     */
    Set<String> getAllTerms();

    /**
     * Get all default terms and append some additional terms
     */
    Set<String> getAllTermsWithAdditional(String[] terms);
}
