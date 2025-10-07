package security.whisper.javastix.datamarkings;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.json.converters.dehydrated.MarkingDefinitionConverter;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.validation.SdoDefaultValidator;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.io.Serializable;
import java.util.Set;

@Value.Immutable @Serial.Version(1L)
@Value.Style(typeAbstract="*Dm", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, depluralize = true)
@JsonSerialize(as = GranularMarking.class) @JsonDeserialize(builder = GranularMarking.Builder.class)
@Redactable
public interface GranularMarkingDm extends StixCustomProperties, SdoDefaultValidator, Serializable {

    @NotNull
    @JsonProperty("marking_ref")
    @JsonIdentityInfo(generator= ObjectIdGenerators.PropertyGenerator.class, property="id")
    @JsonIdentityReference(alwaysAsId=true)
    @JsonDeserialize(converter = MarkingDefinitionConverter.class)
    MarkingDefinitionDm getMarkingRef();

    @Size(min = 1, message = "Must have as least 1 selector")
    @JsonProperty("selectors")
    default Set<String> getSelectors() {
        return null;
    }

}
