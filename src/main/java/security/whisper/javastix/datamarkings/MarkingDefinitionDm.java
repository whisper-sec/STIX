package security.whisper.javastix.datamarkings;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.common.StixCommonProperties;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.datamarkings.objects.StatementMarkingObject;
import security.whisper.javastix.datamarkings.objects.TlpMarkingObject;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.constraints.markingdefinitiontype.MarkingDefinitionTypeLimit;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
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

