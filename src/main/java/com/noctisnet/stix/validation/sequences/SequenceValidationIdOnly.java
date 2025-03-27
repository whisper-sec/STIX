package com.noctisnet.stix.validation.sequences;

import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import com.noctisnet.stix.validation.groups.ValidateIdOnly;

import javax.validation.GroupSequence;

@GroupSequence({DefaultValuesProcessor.class, ValidateIdOnly.class})
public interface SequenceValidationIdOnly {
}
