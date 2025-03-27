package com.noctisnet.stix.datamarkings.objects;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.datamarkings.StixMarkingObject;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.validation.GenericValidation;
import com.noctisnet.stix.validation.constraints.vocab.Vocab;
import com.noctisnet.stix.vocabulary.vocabularies.TlpLevels;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;

@Value.Immutable @Serial.Version(1L)
@Value.Style(typeImmutable = "Tlp", additionalJsonAnnotations = {JsonTypeName.class}, validationMethod = Value.Style.ValidationMethod.NONE, depluralize = true)
@JsonSerialize(as = Tlp.class) @JsonDeserialize(builder = Tlp.Builder.class)
@Redactable
@JsonTypeName("tlp")
public interface TlpMarkingObject extends GenericValidation, StixMarkingObject {

    @NotNull
    @JsonProperty("tlp")
    @Vocab(TlpLevels.class)
    String getTlp();

}
