package security.whisper.javastix.sro.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.json.converters.dehydrated.BundleableObjectConverter;
import security.whisper.javastix.redaction.Redactable;
import security.whisper.javastix.sdo.DomainObject;
import security.whisper.javastix.sdo.objects.*;
import security.whisper.javastix.sro.RelationshipObject;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.constraints.relationship.RelationshipLimit;
import security.whisper.javastix.validation.constraints.relationship.RelationshipTypeLimit;
import security.whisper.javastix.validation.constraints.vocab.Vocab;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import security.whisper.javastix.vocabulary.vocabularies.RelationshipTypes;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.Optional;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * relationship
 * <p>
 * The Relationship object is used to link together two STIX Objects (SDOs or SCOs) in order to describe how they are related to each other.
 * According to STIX 2.1 specification, relationships can be created between:
 * - SDO to SDO
 * - SDO to SCO
 * - SCO to SCO
 *
 */
@Value.Immutable @Serial.Version(1L)
@Value.Style(typeAbstract="*Sro", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@DefaultTypeValue(value = "relationship", groups = {DefaultValuesProcessor.class})
@JsonTypeName("relationship")
@JsonSerialize(as = Relationship.class) @JsonDeserialize(builder = Relationship.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created",
        "modified", "revoked", "labels", "external_references",
        "object_marking_refs", "granular_markings", "relationship_type", "description",
        "source_ref", "target_ref"})
@Redactable
//@TODO Refactor RelationshipTypeLimit and RelationshipLimit as they are partially redundant
@RelationshipTypeLimit(source = AttackPatternSdo.class, relationshipTypes = {"targets", "uses"})
@RelationshipTypeLimit(source = CampaignSdo.class, relationshipTypes = {"attributed-to", "targets", "uses"})
@RelationshipTypeLimit(source = CourseOfActionSdo.class, relationshipTypes = {"mitigates"})
@RelationshipTypeLimit(source = IdentitySdo.class, relationshipTypes = {"targets", "attributed-to", "impersonates"})
@RelationshipTypeLimit(source = IndicatorSdo.class, relationshipTypes = {"indicates"})
@RelationshipTypeLimit(source = IntrusionSetSdo.class, relationshipTypes = {"attributed-to", "targets", "uses"})
@RelationshipTypeLimit(source = MalwareSdo.class, relationshipTypes = {"targets", "uses", "variant-of"})
@RelationshipTypeLimit(source = ThreatActorSdo.class, relationshipTypes = {"attributed-to", "impersonates", "targets", "uses"})
@RelationshipTypeLimit(source = ToolSdo.class, relationshipTypes = {"targets"})
@RelationshipLimit(source = DomainObject.class, relationshipType = "derived-from", target = {DomainObject.class}, classEquality = true)
@RelationshipLimit(source = DomainObject.class, relationshipType = "duplicate-of", target = {DomainObject.class}, classEquality = true)
@RelationshipLimit(source = DomainObject.class, relationshipType = "related-to", target = {DomainObject.class})
@RelationshipLimit(source = AttackPatternSdo.class, relationshipType = "targets", target = {IdentitySdo.class, VulnerabilitySdo.class})
@RelationshipLimit(source = AttackPatternSdo.class, relationshipType = "uses", target = {MalwareSdo.class, ToolSdo.class})
@RelationshipLimit(source = CampaignSdo.class, relationshipType = "attributed-to", target = {IntrusionSetSdo.class, ThreatActorSdo.class})
@RelationshipLimit(source = CampaignSdo.class, relationshipType = "targets", target = {IdentitySdo.class, VulnerabilitySdo.class})
@RelationshipLimit(source = CampaignSdo.class, relationshipType = "uses", target = {AttackPatternSdo.class, MalwareSdo.class, ToolSdo.class})
@RelationshipLimit(source = CourseOfActionSdo.class, relationshipType = "mitigates", target = {AttackPatternSdo.class, MalwareSdo.class, ToolSdo.class, VulnerabilitySdo.class})
@RelationshipLimit(source = IndicatorSdo.class, relationshipType = "indicates", target = {AttackPatternSdo.class, CampaignSdo.class, IntrusionSetSdo.class, MalwareSdo.class, ThreatActorSdo.class, ToolSdo.class})
@RelationshipLimit(source = IntrusionSetSdo.class, relationshipType = "attributed-to", target = {ThreatActorSdo.class})
@RelationshipLimit(source = IntrusionSetSdo.class, relationshipType = "targets", target = {IdentitySdo.class, VulnerabilitySdo.class})
@RelationshipLimit(source = IntrusionSetSdo.class, relationshipType = "uses", target = {AttackPatternSdo.class, MalwareSdo.class, ToolSdo.class})
@RelationshipLimit(source = MalwareSdo.class, relationshipType = "targets", target = {IdentitySdo.class, VulnerabilitySdo.class})
@RelationshipLimit(source = MalwareSdo.class, relationshipType = "uses", target = {ToolSdo.class})
@RelationshipLimit(source = MalwareSdo.class, relationshipType = "variant-of", target = {MalwareSdo.class})
@RelationshipLimit(source = ThreatActorSdo.class, relationshipType = "attributed-to", target = {IdentitySdo.class})
@RelationshipLimit(source = ThreatActorSdo.class, relationshipType = "impersonates", target = {IdentitySdo.class})
@RelationshipLimit(source = ThreatActorSdo.class, relationshipType = "targets", target = {IdentitySdo.class, VulnerabilitySdo.class})
@RelationshipLimit(source = ThreatActorSdo.class, relationshipType = "uses", target = {AttackPatternSdo.class, MalwareSdo.class, ToolSdo.class})
@RelationshipLimit(source = ToolSdo.class, relationshipType = "targets", target = {IdentitySdo.class, VulnerabilitySdo.class})
// Generic COO and mixed relationships - supports STIX 2.1 SCO relationships
public interface RelationshipSro extends RelationshipObject {

    @NotBlank
    @Vocab(RelationshipTypes.class)
    @JsonProperty("relationship_type")
	@JsonPropertyDescription("The name used to identify the type of relationship.")
    @Redactable(useMask = true)
    String getRelationshipType();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
	@JsonPropertyDescription("A description that helps provide context about the relationship.")
    @Redactable
    Optional<String> getDescription();

    @NotNull
    @JsonProperty("source_ref")
	@JsonPropertyDescription("The ID of the source (from) object. Can be either an SDO or SCO.")
    @JsonIdentityInfo(generator= ObjectIdGenerators.PropertyGenerator.class, property="id")
    @JsonIdentityReference(alwaysAsId=true)
    @JsonDeserialize(converter = BundleableObjectConverter.class)
    @Redactable(useMask = true)
    BundleableObject getSourceRef();

    @NotNull
    @JsonProperty("target_ref")
	@JsonPropertyDescription("The ID of the target (to) object. Can be either an SDO or SCO.")
    @JsonIdentityInfo(generator= ObjectIdGenerators.PropertyGenerator.class, property="id")
    @JsonIdentityReference(alwaysAsId=true)
    @JsonDeserialize(converter = BundleableObjectConverter.class)
    @Redactable(useMask = true)
    BundleableObject getTargetRef();

}
