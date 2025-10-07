package security.whisper.javastix.sdo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import security.whisper.javastix.common.StixCommonProperties;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.common.StixLabels;
import security.whisper.javastix.common.StixModified;
import security.whisper.javastix.common.StixRevoked;
import security.whisper.javastix.sro.objects.RelationshipSro;

import javax.validation.constraints.NotNull;
import org.immutables.value.Value;
import java.io.Serializable;
import java.util.Collections;
import java.util.Set;

/**
 * Base interface used by Immutable STIX Domain Objects.
 * Implements StixObject through StixCommonProperties which extends BundleableObject.
 */
public interface DomainObject extends Serializable,
                                      StixCommonProperties,
                                      StixCustomProperties,
                                      StixLabels,
                                      StixModified,
                                      StixRevoked {

    /**
     * This is used with the SROs.  The SRO interface enforces what relationships can be created.  The Relationships can then be stored in the Domain object if they choose.
     * Otherwise you would typically add these Relationship SROs that are specific to SDOs, can be grabbed during bundle creation.
     *
     * @return Set of Relationship SROs
     */
    @Value.Default
    @NotNull
    @JsonIgnore
    default Set<RelationshipSro> getRelationships() {
        return Collections.emptySet();
    }

}
