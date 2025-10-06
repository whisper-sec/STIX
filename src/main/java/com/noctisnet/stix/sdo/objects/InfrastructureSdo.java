package com.noctisnet.stix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.common.StixInstant;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.sdo.DomainObject;
import com.noctisnet.stix.sdo.types.KillChainPhaseType;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.constraints.vocab.Vocab;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import com.noctisnet.stix.vocabulary.vocabularies.InfrastructureTypes;
import org.hibernate.validator.constraints.Length;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * infrastructure
 * <p>
 * The Infrastructure SDO represents a type of TTP and describes any systems, software services,
 * and associated physical or virtual resources intended to support some purpose (e.g., C2 servers
 * used as part of an attack, drive-by download websites, etc.).
 * This object is part of STIX 2.1 specification.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("infrastructure")
@DefaultTypeValue(value = "infrastructure", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE,
             additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Infrastructure.class) @JsonDeserialize(builder = Infrastructure.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created", "modified", "revoked", "labels",
        "external_references", "object_marking_refs", "granular_markings",
        "name", "description", "infrastructure_types", "aliases", "kill_chain_phases",
        "first_seen", "last_seen"})
@Redactable
public interface InfrastructureSdo extends DomainObject {

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("The name used to identify the Infrastructure.")
    @Redactable
    String getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description that provides more details and context about the Infrastructure, potentially including its purpose and its key characteristics.")
    @Redactable
    Optional<String> getDescription();

    @NotNull
    @Size(min = 1)
    @Vocab(InfrastructureTypes.class)
    @JsonProperty("infrastructure_types")
    @JsonPropertyDescription("The type of infrastructure being described. Open Vocabulary: infrastructure-type-ov")
    @Redactable(useMask = true)
    Set<@Length(min = 1) String> getInfrastructureTypes();

    @JsonProperty("aliases") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("Alternative names used to identify this Infrastructure.")
    @Redactable
    default Set<String> getAliases() {
        return null;
    }

    @JsonProperty("kill_chain_phases") @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The list of kill chain phases for which this Infrastructure is used.")
    @Redactable
    default Set<KillChainPhaseType> getKillChainPhases() {
        return null;
    }

    @JsonProperty("first_seen") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Infrastructure was first seen performing malicious activities.")
    @Redactable
    Optional<StixInstant> getFirstSeen();

    @JsonProperty("last_seen") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Infrastructure was last seen performing malicious activities.")
    @Redactable
    Optional<StixInstant> getLastSeen();
}
