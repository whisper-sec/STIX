package security.whisper.javastix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.sdo.types.KillChainPhaseType;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.constraints.vocab.Vocab;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import security.whisper.javastix.vocabulary.vocabularies.ToolLabels;
import org.hibernate.validator.constraints.Length;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * tool
 * <p>
 * Tools are legitimate software that can be used by threat actors to perform attacks.
 * This SDO MUST NOT be used to characterize malware. 
 * Further, Tool MUST NOT be used to characterise tools used as part of a course of action in response to an attack.
 * 
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("tool")
@DefaultTypeValue(value = "tool", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Tool.class) @JsonDeserialize(builder = Tool.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "external_references",
        "object_marking_refs", "granular_markings", "name",
        "description", "kill_chain_phases", "tool_version"})
@Redactable
public interface ToolSdo extends DomainObject {

    @Override
    @Value.Default
    @NotNull
    @Vocab(ToolLabels.class)
    @JsonPropertyDescription("The kind(s) of tool(s) being described. Open Vocab - tool-label-ov")
    @Redactable(useMask = true)
    default Set<@Length(min = 1) String> getLabels() {
        return Collections.emptySet();
    }

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("The name used to identify the Tool.")
    @Redactable(useMask = true)
    String getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("Provides more context and details about the Tool object.")
    @Redactable
    Optional<String> getDescription();

    @Value.Default
    @NotNull
    @JsonProperty("kill_chain_phases")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The list of kill chain phases for which this Tool instance can be used.")
    @Redactable
    default Set<KillChainPhaseType> getKillChainPhases() {
        return Collections.emptySet();
    }

    @JsonProperty("tool_version") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The version identifier associated with the tool.")
    @Redactable
    Optional<String> getToolVersion();

}
