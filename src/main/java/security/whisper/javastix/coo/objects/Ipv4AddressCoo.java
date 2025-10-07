package security.whisper.javastix.coo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.coo.CyberObservableObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * ipv4-addr
 * <p>
 * The IPv4 Address Object represents one or more IPv4 addresses expressed using CIDR notation.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "ipv4-addr", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Coo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
@JsonTypeName("ipv4-addr")
@JsonSerialize(as = Ipv4Address.class) @JsonDeserialize(builder = Ipv4Address.Builder.class)
@JsonPropertyOrder({"type", "extensions", "value", "resolves_to_refs", "belongs_to_refs"})
public interface Ipv4AddressCoo extends CyberObservableObject {
    // TODO  Consider using regexp to validate:
    // http://blog.markhatton.co.uk/2011/03/15/regular-expressions-for-ip-addresses-cidr-ranges-and-hostnames/

    /**
     * If a given IPv4 Address Object represents a single IPv4 address, the CIDR /32 suffix MAY be omitted.
     * (Required)
     *
     */
    @JsonProperty("value")
    @JsonPropertyDescription("Specifies one or more IPv4 addresses expressed using CIDR notation.")
    @NotNull
    String getValue();

    /**
     * The objects referenced in this list MUST be of type mac-addr.
     */
    @JsonProperty("resolves_to_refs")
    @JsonPropertyDescription("Specifies a list of references to one or more Layer 2 Media Access Control (MAC) addresses that the IPv4 address resolves to.")
    default Set<String> getResolvesToRefs() {
        return null;
    }

    /**
     * The objects referenced in this list MUST be of type autonomous-system.
     */
    @JsonProperty("belongs_to_refs")
    @JsonPropertyDescription("Specifies a reference to one or more autonomous systems (AS) that the IPv4 address belongs to.")
    default Set<String> getBelongsToRefs() {
        return null;
    }

    /**
     * Deterministically generates the ID for this IPv4 address based on its value.
     */
    @Override
    @Value.Derived
    default String getId() {
        return "ipv4-addr--" + UUID.nameUUIDFromBytes(getValue().getBytes(StandardCharsets.UTF_8));
    }

}
