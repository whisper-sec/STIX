package com.noctisnet.stix.datamarkings;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.common.StixCommonProperties;
import com.noctisnet.stix.common.StixCustomProperties;
import com.noctisnet.stix.datamarkings.objects.StatementMarkingObject;
import com.noctisnet.stix.datamarkings.objects.TlpMarkingObject;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.constraints.markingdefinitiontype.MarkingDefinitionTypeLimit;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;


@Value.Immutable
@Serial.Version(1L)
@JsonTypeName("marking-definition")
@DefaultTypeValue(value = "marking-definition", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract = "*Dm", typeImmutable = "*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = MarkingDefinition.class)
@JsonDeserialize(builder = MarkingDefinition.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "external_references", "object_marking_refs", "granular_markings", "definition_type",
        "definition"})
@MarkingDefinitionTypeLimit(markingObject = TlpMarkingObject.class, markingDefinitionType = "tlp", groups = {DefaultValuesProcessor.class})
@MarkingDefinitionTypeLimit(markingObject = StatementMarkingObject.class, markingDefinitionType = "statement", groups = {DefaultValuesProcessor.class})
@Redactable
public interface MarkingDefinitionDm extends StixCommonProperties, StixCustomProperties {

    @NotBlank
    @JsonProperty("definition_type")
    String getDefinitionType();

    @NotNull
    @JsonProperty("definition")
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "definition_type", include = JsonTypeInfo.As.EXTERNAL_PROPERTY)
    StixMarkingObject getDefinition();

}

