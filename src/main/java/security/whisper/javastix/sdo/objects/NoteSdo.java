package security.whisper.javastix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * note
 * <p>
 * A Note is intended to convey informative text to provide further context and/or to provide additional analysis
 * on the objects referenced by the note. Notes are not intended to be used for embedding other information objects,
 * such as other STIX Objects.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("note")
@DefaultTypeValue(value = "note", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Note.class) @JsonDeserialize(builder = Note.Builder.class)
@JsonPropertyOrder({"type", "spec_version", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "confidence", "external_references",
        "object_marking_refs", "granular_markings", "content", "authors", "object_refs"})
@Redactable
public interface NoteSdo extends DomainObject {

    @NotBlank
    @JsonProperty("content")
    @JsonPropertyDescription("The content of the note.")
    @Redactable
    String getContent();

    @JsonProperty("authors") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The name of the author(s) of this note (e.g., the analyst(s) that created it).")
    @Redactable
    Set<String> getAuthors();

    @NotNull
    @JsonProperty("object_refs") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The objects that the note is being applied to.")
    @Redactable
    Set<BundleableObject> getObjectRefs();

}