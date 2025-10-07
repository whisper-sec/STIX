package security.whisper.javastix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.sdo.types.KillChainPhaseType;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.constraints.vocab.Vocab;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import security.whisper.javastix.vocabulary.vocabularies.IndicatorLabels;
import security.whisper.javastix.vocabulary.vocabularies.IndicatorTypes;
import org.hibernate.validator.constraints.Length;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * indicator
 * <p>
 * Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity.
 * 
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("indicator")
@DefaultTypeValue(value = "indicator", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Indicator.class) @JsonDeserialize(builder = Indicator.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "confidence", "external_references",
        "object_marking_refs", "granular_markings", "indicator_types", "name",
        "description", "pattern", "pattern_type", "valid_from", "valid_until",
        "kill_chain_phases"})
@Redactable
public interface IndicatorSdo extends DomainObject {

    @Override
    @NotNull
    @Size(min = 1)
    @Vocab(IndicatorLabels.class)
    @JsonPropertyDescription("This field is an Open Vocabulary that specifies the type of indicator. Open vocab - indicator-label-ov")
    @Redactable(useMask = true)
    Set<@Length(min = 1) String> getLabels();

    @JsonProperty("indicator_types") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @Vocab(IndicatorTypes.class)
    @JsonPropertyDescription("This field is an Open Vocabulary that specifies the type of indicator. Open vocab - indicator-type-ov")
    @Redactable
    Set<String> getIndicatorTypes();

    @JsonProperty("confidence") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("This field identifies the confidence that the creator has in the correctness of their data. The value ranges from 0 (no confidence) to 100 (complete confidence).")
    @Redactable
    Optional<Integer> getConfidence();

    @JsonProperty("name") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The name used to identify the Indicator.")
    @Redactable
    Optional<String> getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description that provides more details and context about this Indicator, potentially including its purpose and its key characteristics.")
    @Redactable
    Optional<String> getDescription();

    @NotBlank
    @JsonProperty("pattern")
    @JsonPropertyDescription("The detection pattern for this indicator. The default language is STIX Patterning.")
    @Redactable(useMask = true)
    String getPattern();

    @JsonProperty("pattern_type") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The pattern language used in this indicator. The default is 'stix' which represents STIX Patterning.")
    @Redactable
    @Value.Default
    default String getPatternType() {
        return "stix";
    }

    @NotNull
    @JsonProperty("valid_from")
    @JsonPropertyDescription("The time from which this indicator should be considered valuable intelligence.")
    @Redactable(useMask = true)
    StixInstant getValidFrom();

    @JsonProperty("valid_until") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time at which this indicator should no longer be considered valuable intelligence.")
    @Redactable
    Optional<StixInstant> getValidUntil();

    @NotNull
    @JsonProperty("kill_chain_phases")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The list of kill chain phases for which this attack pattern is used.")
    @Redactable
    Set<KillChainPhaseType> getKillChainPhases();

}
