package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Processor Architecture is an open vocabulary that describes different processor architectures
 * for systems that malware or other software might be compiled for or that might be targeted.
 */
public class ProcessorArchitecture implements StixVocabulary {

    @JsonProperty("processor_architecture_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "x86",       // 32-bit x86 architecture
            "x86-64",    // 64-bit x86 architecture (also known as x64, AMD64, Intel 64)
            "ia-64",     // Intel Itanium architecture
            "arm",       // ARM 32-bit architecture
            "arm64",     // ARM 64-bit architecture (also known as AArch64)
            "mips",      // MIPS architecture
            "powerpc",   // PowerPC architecture
            "sparc",     // SPARC architecture
            "alpha",     // DEC Alpha architecture
            "s390x"      // IBM System z architecture
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