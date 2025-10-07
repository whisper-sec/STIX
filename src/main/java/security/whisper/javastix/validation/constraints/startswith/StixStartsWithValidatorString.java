package security.whisper.javastix.validation.constraints.startswith;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class StixStartsWithValidatorString implements ConstraintValidator<StartsWith, String> {

    private String prefix;

    @Override
    public void initialize(StartsWith startsWithConstraint) {
        prefix = startsWithConstraint.value();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext cxt) {
        if (value.startsWith(prefix)){
            return true;
        } else{
            cxt.disableDefaultConstraintViolation();
            String violationMessage = "StartsWith violation: string must start with value: "
                    + prefix + ", but provided value: " + value;
            cxt.buildConstraintViolationWithTemplate(violationMessage).addConstraintViolation();
            return false;
        }
    }
}
