package security.whisper.javastix.datamarkings.objects;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.datamarkings.StixMarkingObject;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.validation.GenericValidation;
import security.whisper.javastix.validation.constraints.vocab.Vocab;
import security.whisper.javastix.vocabulary.vocabularies.TlpLevels;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotNull;

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
