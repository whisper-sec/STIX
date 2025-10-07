package security.whisper.javastix.validation.constraints.vocab;

import security.whisper.javastix.vocabulary.StixVocabulary;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;

/**
 * <p>Provides STIX Vocabulary validation for {@code String} and {@code Set<String>} fields.</p>
 * <br>
 * <p>Value is the vocabulary class to be used for validation.
 * The class must implement {@link StixVocabulary} interface.</p>
 * <br>
 * <p>Example usage: {@code @HashingVocab(AttackMotivations.class)}</p>
 */
@Documented
@Constraint(validatedBy = {
        StixVocabValidatorString.class,
        StixVocabValidatorCollection.class,
        StixVocabValidatorOptionalString.class
})
@Target( { METHOD, FIELD, TYPE_USE, ANNOTATION_TYPE, PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
public @interface Vocab {
    String message() default "{io.digitalstate.stix.validation.contraints.VocabContains}";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    Class<? extends StixVocabulary>  value();

}
