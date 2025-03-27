package com.noctisnet.stix.sdo.objects;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.common.StixInstant;
import com.noctisnet.stix.coo.CyberObservableObject;
import com.noctisnet.stix.coo.json.observables.CyberObservableSetFieldDeserializer;
import com.noctisnet.stix.coo.json.observables.CyberObservableSetFieldSerializer;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.sdo.DomainObject;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import org.hibernate.validator.constraints.Range;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import javax.validation.constraints.Size;
import java.util.Set;
/**
 * observed-data
 * <p>
 * Observed data conveys information that was observed on systems and networks, such as log data or network traffic, using the Cyber Observable specification.
 * 
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("observed-data")
@DefaultTypeValue(value = "observed-data", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = ObservedData.class) @JsonDeserialize(builder = ObservedData.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "external_references",
        "object_marking_refs", "granular_markings", "first_observed", "last_observed",
        "number_observed", "objects"})
@Redactable
public interface ObservedDataSdo extends DomainObject {

    @NotNull
    @JsonProperty("first_observed")
    @JsonPropertyDescription("The beginning of the time window that the data was observed during.")
    @Redactable(useMask = true)
    StixInstant getFirstObserved();

    @NotNull
    @JsonProperty("last_observed")
    @JsonPropertyDescription("The end of the time window that the data was observed during.")
    @Redactable(useMask = true)
    StixInstant getLastObserved();

    @NotNull @Positive
    @JsonProperty("number_observed")
    @JsonPropertyDescription("The number of times the data represented in the objects property was observed. This MUST be an integer between 1 and 999,999,999 inclusive.")
    @Redactable(useMask = true)
    @Range(min = 1, max = 999999999)
    Integer getNumberObserved();

    @NotNull
    @Size(min = 1, message = "At least one Cyber Observable Reference must be provided")
    @JsonProperty("objects")
    @JsonPropertyDescription("A dictionary of Cyber Observable Objects that describes the single 'fact' that was observed.")
    @Redactable(useMask = true)
    @JsonSerialize(using = CyberObservableSetFieldSerializer.class)
    @JsonDeserialize(using = CyberObservableSetFieldDeserializer.class)
    default Set<CyberObservableObject> getObjects() {
        return null;
    }

}
