package com.noctisnet.stix.validation.sequences;

import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;

import javax.validation.GroupSequence;
import javax.validation.groups.Default;

@GroupSequence({DefaultValuesProcessor.class, Default.class})
public interface SequenceDefault {
}
