package security.whisper.javastix.validation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.validation.sequences.SequenceDefault;
import security.whisper.javastix.validation.sequences.SequenceValidationIdOnly;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Set;

public interface SdoDefaultValidator {

    Logger logger = LoggerFactory.getLogger(SdoDefaultValidator.class);
    Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

    default void validate() throws ConstraintViolationException{
        logger.debug("Validating SDO object: {}", this.getClass().getSimpleName());
        Set<ConstraintViolation<SdoDefaultValidator>> violations = VALIDATOR.validate(this, SequenceDefault.class);
        if (!violations.isEmpty()) {
            logger.error("Validation failed with {} violations for {}", violations.size(), this.getClass().getSimpleName());
            violations.forEach(v -> logger.error("  - {}: {}", v.getPropertyPath(), v.getMessage()));
            throw new ConstraintViolationException(violations);
        }
        logger.debug("Validation successful for {}", this.getClass().getSimpleName());
    }

    default void validateOnlyId() throws ConstraintViolationException{
        logger.debug("Validating SDO ID only for: {}", this.getClass().getSimpleName());
        Set<ConstraintViolation<SdoDefaultValidator>> violations = VALIDATOR.validate(this, SequenceValidationIdOnly.class);
        if (!violations.isEmpty()) {
            logger.error("ID validation failed with {} violations for {}", violations.size(), this.getClass().getSimpleName());
            violations.forEach(v -> logger.error("  - {}: {}", v.getPropertyPath(), v.getMessage()));
            throw new ConstraintViolationException(violations);
        }
        logger.debug("ID validation successful for {}", this.getClass().getSimpleName());
    }
}




