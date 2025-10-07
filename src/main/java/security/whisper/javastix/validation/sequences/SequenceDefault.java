package security.whisper.javastix.validation.sequences;

import security.whisper.javastix.validation.groups.DefaultValuesProcessor;

import javax.validation.GroupSequence;
import javax.validation.groups.Default;

@GroupSequence({DefaultValuesProcessor.class, Default.class})
public interface SequenceDefault {
}
