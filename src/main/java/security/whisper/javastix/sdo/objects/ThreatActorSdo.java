package security.whisper.javastix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.constraints.vocab.Vocab;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import security.whisper.javastix.vocabulary.vocabularies.AttackMotivations;
import security.whisper.javastix.vocabulary.vocabularies.AttackResourceLevels;
import security.whisper.javastix.vocabulary.vocabularies.ThreatActorLabels;
import security.whisper.javastix.vocabulary.vocabularies.ThreatActorRoles;
import security.whisper.javastix.vocabulary.vocabularies.ThreatActorSophistication;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * threat-actor
 * <p>
 * Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.
 * 
 */
@Value.Immutable @Serial.Version(1L)
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true, depluralizeDictionary = {"alias:aliases"})
@JsonTypeName("threat-actor")
@DefaultTypeValue(value = "threat-actor", groups = {DefaultValuesProcessor.class})
@JsonSerialize(as = ThreatActor.class) @JsonDeserialize(builder = ThreatActor.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "external_references",
        "object_marking_refs", "granular_markings", "uses", "name",
        "description", "aliases", "roles", "goals", "sophistication",
        "resource_level", "primary_motivation", "secondary_motivation", "personal_motivations"})
@Redactable
public interface ThreatActorSdo extends DomainObject {

    @Override
    @Value.Default
    @NotNull
    @Size(min = 1, message = "Must have at least one value from threat-actor-label-ov")
    @Vocab(ThreatActorLabels.class)
    @JsonPropertyDescription("This field specifies the type of threat actor. Open Vocab - threat-actor-label-ov")
    @Redactable(useMask = true)
    default Set<@Size(min = 1) String> getLabels() {
        return Collections.emptySet();
    }

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("A name used to identify this Threat Actor or Threat Actor group.")
    @Redactable(useMask = true)
    String getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A description that provides more details and context about the Threat Actor.")
    @Redactable
    Optional<String> getDescription();

    @Value.Default
    @NotNull
    @JsonProperty("aliases")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("A list of other names that this Threat Actor is believed to use.")
    @Redactable
    default Set<String> getAliases() {
        return Collections.emptySet();
    }

    @Value.Default
    @NotNull
    @Vocab(ThreatActorRoles.class)
    @JsonProperty("roles")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("This is a list of roles the Threat Actor plays. Open Vocab - threat-actor-role-ov")
    @Redactable
    default Set<String> getRoles() {
        return Collections.emptySet();
    }

    @Value.Default
    @NotNull
    @JsonProperty("goals")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The high level goals of this Threat Actor, namely, what are they trying to do.")
    @Redactable
    default Set<@Size(min = 1) String> getGoals() {
        return Collections.emptySet();
    }

    @NotNull
    @JsonProperty("sophistication") @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack. Open Vocab - threat-actor-sophistication-ov")
    @Redactable
    Optional<@Vocab(ThreatActorSophistication.class) String> getSophistication();

    @JsonProperty("resource_level") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("This defines the organizational level at which this Threat Actor typically works. Open Vocab - attack-resource-level-ov")
    @Redactable
    Optional<@Vocab(AttackResourceLevels.class) String> getResourceLevel();

    @JsonProperty("primary_motivation") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The primary reason, motivation, or purpose behind this Threat Actor. Open Vocab - attack-motivation-ov")
    @Redactable
    Optional<@Vocab(AttackMotivations.class) String> getPrimaryMotivation();

    @Value.Default
    @NotNull
    @Vocab(AttackMotivations.class)
    @JsonProperty("secondary_motivations")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The secondary reasons, motivations, or purposes behind this Threat Actor. Open Vocab - attack-motivation-ov")
    @Redactable
    default Set<String> getSecondaryMotivations() {
        return Collections.emptySet();
    }

    @Value.Default
    @NotNull
    @Vocab(AttackMotivations.class)
    @JsonProperty("personal_motivations")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals. Open Vocab - attack-motivation-ov")
    @Redactable
    default Set<String> getPersonalMotivations() {
        return Collections.emptySet();
    }

}
