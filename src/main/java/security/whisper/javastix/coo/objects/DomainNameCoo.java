package security.whisper.javastix.coo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.coo.CyberObservableObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * domain-name
 * <p>
 * The Domain Name represents the properties of a network domain name.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "domain-name", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Coo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonTypeName("domain-name")
@JsonSerialize(as = DomainName.class) @JsonDeserialize(builder = DomainName.Builder.class)
@JsonPropertyOrder({"type", "extensions", "value", "resolves_to_refs"})
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
public interface DomainNameCoo extends CyberObservableObject {

    @JsonProperty("value")
    @JsonPropertyDescription("Specifies the value of the domain name.")
    @NotNull
    String getValue();

    @Value.Default
    @JsonProperty("resolves_to_refs")
    @JsonPropertyDescription("Specifies a list of references to one or more IP addresses or domain names that the domain name resolves to.")
    default Set<String> getResolvesToRefs() {
        return Collections.emptySet();
    }

    /**
     * Deterministically generates the ID for this domain name based on its value.
     */
    @Override
    @Value.Derived
    default String getId() {
        return "domain-name--" + UUID.nameUUIDFromBytes(getValue().getBytes(StandardCharsets.UTF_8));
    }
}
