package security.whisper.javastix.coo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.coo.CyberObservableObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * autonomous-system
 * <p>
 * The AS object represents the properties of an Autonomous Systems (AS).
 * 
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "autonomous-system", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Coo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonTypeName("autonomous-system")
@JsonSerialize(as = AutonomousSystem.class) @JsonDeserialize(builder = AutonomousSystem.Builder.class)
@JsonPropertyOrder({"type", "extensions", "number", "name", "rir"})
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
public interface AutonomousSystemCoo extends CyberObservableObject {

    @JsonProperty("number")
    @JsonPropertyDescription("Specifies the number assigned to the AS. Such assignments are typically performed by a Regional Internet Registries (RIR)")
    Long getNumber();

    @JsonProperty("name")
    @JsonPropertyDescription("Specifies the name of the AS.")
    Optional<String> getName();

    @JsonProperty("rir")
    @JsonPropertyDescription("Specifies the name of the Regional Internet Registry (RIR) that assigned the number to the AS.")
    Optional<String> getRir();

    /**
     * Deterministically generates the ID for this autonomous system based on its number.
     */
    @Override
    @Value.Derived
    default String getId() {
        return "autonomous-system--" + UUID.nameUUIDFromBytes(String.valueOf(getNumber()).getBytes(StandardCharsets.UTF_8));
    }

}
