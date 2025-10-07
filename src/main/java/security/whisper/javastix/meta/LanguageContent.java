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

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.io.Serializable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * language-content
 * <p>
 * The Language Content object represents text content for STIX Objects represented in languages
 * other than English. Language Content contains a single property (other than the common properties)
 * which is a dictionary that maps language codes to the actual text in that language.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("language-content")
@DefaultTypeValue(value = "language-content", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="LanguageContent", typeImmutable="LanguageContentObject", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = LanguageContentObject.class) @JsonDeserialize(builder = LanguageContentObject.Builder.class)
@JsonPropertyOrder({"type", "spec_version", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "confidence", "external_references",
        "object_marking_refs", "granular_markings", "object_ref", "object_modified",
        "contents"})
@Redactable
public interface LanguageContent extends Serializable, BundleableObject, StixCustomProperties, Stix {

    @NotBlank
    @JsonProperty("type")
    @JsonPropertyDescription("The type property identifies the type of STIX Object. The value must be 'language-content'.")
    @Pattern(regexp = "^language-content$")
    default String getType() {
        return "language-content";
    }

    @NotBlank
    @JsonProperty("id")
    @JsonPropertyDescription("Specifies the identifier for this Language Content object.")
    @Pattern(regexp = "^language-content--")
    String getId();

    @JsonProperty("spec_version")
    @JsonPropertyDescription("The version of the STIX specification used to represent this object.")
    @NotNull
    @Value.Default
    default String getSpecVersion() {
        return "2.1";
    }

    @JsonProperty("created_by_ref") @JsonInclude(value = NON_EMPTY)
    @JsonPropertyDescription("The ID of the identity that created this language content object.")
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
    @JsonProperty("object_ref")
    @JsonPropertyDescription("Specifies the identifier of the object that this language content applies to.")
    String getObjectRef();

    @NotNull
    @JsonProperty("object_modified")
    @JsonPropertyDescription("Specifies the modified time of the object that this language content applies to.")
    StixInstant getObjectModified();

    @NotNull
    @JsonProperty("contents")
    @JsonPropertyDescription("A dictionary that captures the text content in different languages. The key is the language code and the value is a dictionary containing the translated content.")
    Map<String, Map<String, String>> getContents();

}