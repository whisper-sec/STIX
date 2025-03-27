package com.noctisnet.stix.common;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.noctisnet.stix.redaction.Redactable;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;

/**
 *
 */
@Value.Style(validationMethod = Value.Style.ValidationMethod.NONE)
public interface StixModified {

    @NotNull
    @JsonProperty("modified")
    @JsonPropertyDescription("The modified property represents the time that this particular version of the object was created. The timstamp value MUST be precise to the nearest millisecond.")
    @Value.Default
    @Redactable
    default StixInstant getModified(){
        return new StixInstant();
    }
}
