package security.whisper.javastix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.sdo.types.KillChainPhaseType;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * incident
 * <p>
 * An Incident object describes a security incident that occurred or is in progress.
 * It includes information about the impact, the actors involved, and the timeline of the incident.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("incident")
@DefaultTypeValue(value = "incident", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Incident.class) @JsonDeserialize(builder = Incident.Builder.class)
@JsonPropertyOrder({"type", "spec_version", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "confidence", "external_references",
        "object_marking_refs", "granular_markings", "name", "description",
        "kill_chain_phases", "first_seen", "last_seen", "impact"})
@Redactable
public interface IncidentSdo extends DomainObject {

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("A name used to identify the Incident.")
    @Redactable
    String getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description that provides more details and context about the Incident, potentially including its impact and handling.")
    @Redactable
    Optional<String> getDescription();

    @JsonProperty("kill_chain_phases") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The list of kill chain phases for which this Incident is used.")
    @Size(min = 1)
    @Redactable
    Set<KillChainPhaseType> getKillChainPhases();

    @JsonProperty("first_seen") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Incident was first seen.")
    @Redactable
    Optional<StixInstant> getFirstSeen();

    @JsonProperty("last_seen") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Incident was last seen.")
    @Redactable
    Optional<StixInstant> getLastSeen();

    @JsonProperty("impact") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description of the impact or potential impact of the Incident.")
    @Redactable
    Optional<String> getImpact();

}