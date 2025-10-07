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
import security.whisper.javastix.vocabulary.vocabularies.GroupingContext;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * grouping
 * <p>
 * A Grouping object explicitly asserts that the referenced STIX Objects have a shared context.
 * Grouping objects are used to characterize a set of related STIX Objects that may or may not be
 * directly connected through relationships.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("grouping")
@DefaultTypeValue(value = "grouping", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Grouping.class) @JsonDeserialize(builder = Grouping.Builder.class)
@JsonPropertyOrder({"type", "spec_version", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "confidence", "external_references",
        "object_marking_refs", "granular_markings", "name", "description",
        "context", "object_refs"})
@Redactable
public interface GroupingSdo extends DomainObject {

    @JsonProperty("name") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A name used to identify the Grouping.")
    @Redactable
    Optional<String> getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description that provides more details and context about the Grouping, potentially including a justification for the selection of the objects within the grouping.")
    @Redactable
    Optional<String> getDescription();

    @JsonProperty("context") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A short descriptor of the particular context shared by the content referenced by the Grouping. Open Vocabulary - grouping-context-ov")
    @Vocab(GroupingContext.class)
    @Redactable
    Optional<String> getContext();

    @NotNull
    @Size(min = 1)
    @JsonProperty("object_refs") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("Specifies the list of STIX Objects that are referred to by this Grouping.")
    @Redactable
    Set<BundleableObject> getObjectRefs();

}