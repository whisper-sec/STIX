package security.whisper.javastix.vocabulary.vocabularies;

import com.fasterxml.jackson.annotation.JsonProperty;
import security.whisper.javastix.vocabulary.StixVocabulary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Implementation Language is an open vocabulary that describes programming languages
 * that might be used to implement malware or other software.
 */
public class ImplementationLanguage implements StixVocabulary {

    @JsonProperty("implementation_language_vocabulary")
    private Set<String> terms = new HashSet<>(Arrays.asList(
            "applescript",    // AppleScript
            "bash",           // Bash scripting
            "c",              // C programming language
            "c++",            // C++ programming language
            "c#",             // C# programming language
            "go",             // Go programming language
            "java",           // Java programming language
            "javascript",     // JavaScript
            "lua",            // Lua scripting language
            "objective-c",    // Objective-C
            "perl",           // Perl scripting language
            "php",            // PHP programming language
            "powershell",     // PowerShell scripting
            "python",         // Python programming language
            "ruby",           // Ruby programming language
            "rust",           // Rust programming language
            "scala",          // Scala programming language
            "swift",          // Swift programming language
            "typescript",     // TypeScript
            "visual-basic",   // Visual Basic
            "x86-assembly",   // x86 Assembly language
            "x86-64-assembly" // x86-64 Assembly language
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