package com.noctisnet.stix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.bundle.BundleableObject;
import com.noctisnet.stix.common.StixInstant;
import com.noctisnet.stix.json.converters.dehydrated.BundleableObjectSetConverter;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.sdo.DomainObject;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.constraints.vocab.Vocab;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import com.noctisnet.stix.vocabulary.vocabularies.ReportLabels;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * report
 * <p>
 * Reports are collections of threat intelligence focused on one or more topics, such as a 
 * description of a threat actor, malware, or attack technique, including context and related details.
 * 
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("report")
@DefaultTypeValue(value = "report", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Report.class) @JsonDeserialize(builder = Report.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "external_references",
        "object_marking_refs", "granular_markings", "name", "description",
        "published", "object_refs"})
@Redactable
public interface ReportSdo extends DomainObject {

    @Override
    @NotNull
    @JsonPropertyDescription("This field is an Open Vocabulary that specifies the primary subject of this report. The suggested values for this field are in report-label-ov.")
    @Redactable(useMask = true)
    @Size(min = 1)
    default Set<@Vocab(ReportLabels.class) String> getLabels() {
        return null;
    }

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("A description that provides more details and context about Report.")
    @Redactable(useMask = true)
    String getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description that provides more details and context about Report.")
    @Redactable
    Optional<String> getDescription();

    @NotNull
    @JsonProperty("published")
    @JsonPropertyDescription("The date that this report object was officially published by the creator of this report.")
    @Redactable(useMask = true)
    StixInstant getPublished();

    @NotNull
    @Size(min = 1, message = "Must have at least one Report object reference")
    @JsonProperty("object_refs")
    @JsonPropertyDescription("Specifies the STIX Objects that are referred to by this Report.")
    @JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id")
    @JsonIdentityReference(alwaysAsId = true)
    @JsonDeserialize(converter = BundleableObjectSetConverter.class)
    @Redactable(useMask = true)
    default Set<BundleableObject> getObjectRefs() {
        return null;
    }

}
