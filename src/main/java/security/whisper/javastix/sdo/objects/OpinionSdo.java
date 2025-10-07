package security.whisper.javastix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.constraints.vocab.Vocab;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import security.whisper.javastix.vocabulary.vocabularies.OpinionEnum;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * opinion
 * <p>
 * An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity.
 * The primary property is the opinion property, which captures the level of agreement or disagreement using a fixed scale.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("opinion")
@DefaultTypeValue(value = "opinion", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Opinion.class) @JsonDeserialize(builder = Opinion.Builder.class)
@JsonPropertyOrder({"type", "spec_version", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "confidence", "external_references",
        "object_marking_refs", "granular_markings", "opinion", "explanation",
        "authors", "object_refs"})
@Redactable
public interface OpinionSdo extends DomainObject {

    @NotBlank
    @JsonProperty("opinion")
    @JsonPropertyDescription("The opinion that the producing organization has about the correctness of the information.")
    @Vocab(OpinionEnum.class)
    @Redactable
    String getOpinion();

    @JsonProperty("explanation") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("An explanation of why the producer has this opinion.")
    @Redactable
    Optional<String> getExplanation();

    @JsonProperty("authors") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The name of the author(s) of this opinion (e.g., the analyst(s) that created it).")
    @Redactable
    Set<String> getAuthors();

    @NotNull
    @Size(min = 1)
    @JsonProperty("object_refs") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The STIX Objects that this opinion is being applied to.")
    @Redactable
    Set<BundleableObject> getObjectRefs();

}