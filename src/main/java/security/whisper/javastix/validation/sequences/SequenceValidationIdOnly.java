package security.whisper.javastix.validation.sequences;

import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import security.whisper.javastix.validation.groups.ValidateIdOnly;

import javax.validation.GroupSequence;

@GroupSequence({DefaultValuesProcessor.class, ValidateIdOnly.class})
public interface SequenceValidationIdOnly {
}
