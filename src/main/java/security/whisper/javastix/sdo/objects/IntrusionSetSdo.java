package security.whisper.javastix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.constraints.vocab.Vocab;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import security.whisper.javastix.vocabulary.vocabularies.AttackMotivations;
import security.whisper.javastix.vocabulary.vocabularies.AttackResourceLevels;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * intrusion-set
 * <p>
 * An Intrusion Set is a grouped set of adversary behavior and resources with common properties that is believed to be orchestrated by a single organization.
 * 
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("intrusion-set")
@DefaultTypeValue(value = "intrusion-set", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = IntrusionSet.class) @JsonDeserialize(builder = IntrusionSet.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "external_references",
        "object_marking_refs", "granular_markings", "name", "description", "aliases",
        "first_seen", "last_seen", "goals", "resource_level",
        "primary_motivation", "secondary_motivation"})
@Redactable
public interface IntrusionSetSdo extends DomainObject {

    @NotBlank
    @JsonProperty("name")
    @JsonPropertyDescription("The name used to identify the Intrusion Set.")
    @Redactable(useMask = true)
    String getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("Provides more context and details about the Intrusion Set object.")
    @Redactable
    Optional<String> getDescription();

    @Value.Default
    @NotNull
    @JsonProperty("aliases")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("Alternative names used to identify this Intrusion Set.")
    @Redactable
    default Set<String> getAliases() {
        return Collections.emptySet();
    }

    @JsonProperty("first_seen") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Intrusion Set was first seen.")
    @Redactable
    Optional<StixInstant> getFirstSeen();

    @JsonProperty("last_seen") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The time that this Intrusion Set was last seen.")
    @Redactable
    Optional<StixInstant> getLastSeen();

    @Value.Default
    @NotNull
    @JsonProperty("goals")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The high level goals of this Intrusion Set, namely, what are they trying to do.")
    @Redactable
    default Set<String> getGoals() {
        return Collections.emptySet();
    }

    @JsonProperty("resource_level") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("This defines the organizational level at which this Intrusion Set typically works. Open Vocab - attack-resource-level-ov")
    @Redactable
    Optional<@Vocab(AttackResourceLevels.class) String> getResourceLevel();

    @JsonProperty("primary_motivation") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The primary reason, motivation, or purpose behind this Intrusion Set. Open Vocab - attack-motivation-ov")
    @Redactable
    Optional<@Vocab(AttackMotivations.class) String> getPrimaryMotivation();

    @Value.Default
    @NotNull
    @Vocab(AttackMotivations.class)
    @JsonProperty("secondary_motivations")
    @JsonInclude(NON_EMPTY)
    @JsonPropertyDescription("The secondary reasons, motivations, or purposes behind this Intrusion Set. Open Vocab - attack-motivation-ov")
    @Redactable
    default Set<String> getSecondaryMotivations() {
        return Collections.emptySet();
    }

}
