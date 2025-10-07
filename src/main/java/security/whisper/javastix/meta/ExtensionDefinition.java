package security.whisper.javastix.meta;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.common.Stix;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.datamarkings.GranularMarkingDm;
import security.whisper.javastix.datamarkings.MarkingDefinitionDm;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.types.ExternalReferenceType;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.io.Serializable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * extension-definition
 * <p>
 * The Extension Definition object defines new STIX extensions that can be used to characterize
 * additional properties and behaviors beyond what is defined in the base STIX specification.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("extension-definition")
@DefaultTypeValue(value = "extension-definition", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="ExtensionDefinition", typeImmutable="ExtensionDefinitionObject", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = ExtensionDefinitionObject.class) @JsonDeserialize(builder = ExtensionDefinitionObject.Builder.class)
@JsonPropertyOrder({"type", "spec_version", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "confidence", "external_references",
        "object_marking_refs", "granular_markings", "name", "description",
        "schema", "version", "extension_types", "extension_properties"})
@Redactable
public interface ExtensionDefinition extends Serializable, BundleableObject, StixCustomProperties, Stix {

    @NotBlank
    @JsonProperty("type")
    @JsonPropertyDescription("The type property identifies the type of STIX Object. The value must be 'extension-definition'.")
    @Pattern(regexp = "^extension-definition$")
    default String getType() {
        return "extension-definition";
    }

    @NotBlank
    @JsonProperty("id")
    @JsonPropertyDescription("Specifies the identifier for this Extension Definition object.")
    @Pattern(regexp = "^extension-definition--")
    String getId();

    @JsonProperty("spec_version")
    @JsonPropertyDescription("The version of the STIX specification used to represent this object.")
    @NotNull
    @Value.Default
    default String getSpecVersion() {
        return "2.1";
    }

    @JsonProperty("created_by_ref") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The ID of the identity that created this extension definition.")
    Optional<String> getCreatedByRef();

    @NotNull
    @JsonProperty("created")
    @JsonPropertyDescription("The created property represents the time at which this object was originally created.")
    StixInstant getCreated();

    @NotNull
    @JsonProperty("modified")
    @JsonPropertyDescription("The modified property represents the time at which this object was last modified.")
    StixInstant getModified();

    @JsonProperty("revoked") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The revoked property is a boolean that indicates whether the object has been revoked.")
    Optional<Boolean> getRevoked();

    @JsonProperty("labels") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The labels property specifies a set of categorization labels.")
    Set<String> getLabels();

    @JsonProperty("confidence") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The confidence property identifies the confidence that the creator has in the correctness of their data.")
    Optional<Integer> getConfidence();

    @JsonProperty("external_references") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("A list of external references which refer to non-STIX information.")
    Set<ExternalReferenceType> getExternalReferences();

    @JsonProperty("object_marking_refs") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The list of marking-definition objects to be applied to this object.")
    Set<MarkingDefinitionDm> getObjectMarkingRefs();

    @JsonProperty("granular_markings") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The set of granular markings that apply to this object.")
    Set<GranularMarkingDm> getGranularMarkings();

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("The name of this extension.")
    @Redactable
    String getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("A detailed description of this extension.")
    @Redactable
    Optional<String> getDescription();

    @NotNull
    @JsonProperty("schema")
    @JsonPropertyDescription("The JSON schema for this extension.")
    Map<String, Object> getSchema();

    @NotBlank
    @JsonProperty("version")
    @JsonPropertyDescription("The version of this extension.")
    String getVersion();

    @NotNull
    @JsonProperty("extension_types")
    @JsonPropertyDescription("A list of the types of STIX Objects that this extension can be applied to.")
    Set<String> getExtensionTypes();

    @JsonProperty("extension_properties") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The list of properties that this extension adds to the objects it extends.")
    Set<String> getExtensionProperties();

}