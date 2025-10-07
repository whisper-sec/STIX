package security.whisper.javastix.validation.sequences;

import security.whisper.javastix.validation.groups.DefaultValuesProcessor;

import jakarta.validation.GroupSequence;
import jakarta.validation.groups.Default;

@GroupSequence({DefaultValuesProcessor.class, Default.class})
public interface SequenceDefault {
}
