package security.whisper.javastix.coo;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.immutables.value.Value;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.common.StixSpecVersion;
import security.whisper.javastix.datamarkings.GranularMarkingDm;
import security.whisper.javastix.datamarkings.MarkingDefinitionDm;
import security.whisper.javastix.json.StixParsers;
import security.whisper.javastix.json.converters.dehydrated.MarkingDefinitionSetConverter;
import security.whisper.javastix.validation.constraints.coo.allowedparents.ValidateExtensions;

import jakarta.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Collections;
import java.util.Set;

/**
 * Base interface for STIX Cyber Observable Objects (SCOs).
 * Implements StixObject through BundleableObject.
 * <p>
 * Declares the {@link BundleableObject} members with their STIX 2.1 wire form: the marking
 * properties as {@code object_marking_refs} (identifiers) and {@code granular_markings}, and the
 * library's own {@code hydrated} flag and {@code toJsonString} never written as properties.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type", include = JsonTypeInfo.As.EXISTING_PROPERTY)
@ValidateExtensions
public interface CyberObservableObject extends Serializable,
        CyberObservableObjectCommonProperties,
        StixSpecVersion,
        StixCustomProperties,
        BundleableObject {

    @Override
    @Value.Default
    @NotNull
    @JsonProperty("object_marking_refs")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonPropertyDescription("The list of marking-definition objects to be applied to this object.")
    @JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id")
    @JsonIdentityReference(alwaysAsId = true)
    @JsonDeserialize(converter = MarkingDefinitionSetConverter.class)
    default Set<MarkingDefinitionDm> getObjectMarkingRefs() {
        return Collections.emptySet();
    }

    @Override
    @Value.Default
    @NotNull
    @JsonProperty("granular_markings")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonPropertyDescription("The set of granular markings that apply to this object.")
    default Set<GranularMarkingDm> getGranularMarkings() {
        return Collections.emptySet();
    }

    /**
     * Dictates whether the object is hydrated (fully populated) or only a reference holding its id.
     * Read from input when present, never written.
     */
    @Override
    @Value.Default
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    default boolean getHydrated() {
        return true;
    }

    @Override
    @JsonIgnore
    @Value.Lazy
    @Value.Auxiliary
    default String toJsonString() {
        try {
            return StixParsers.getJsonMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot process JSON", e);
        }
    }

}
