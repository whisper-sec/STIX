package security.whisper.javastix.sro;

import security.whisper.javastix.common.StixCommonProperties;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.common.StixLabels;
import security.whisper.javastix.common.StixModified;
import security.whisper.javastix.common.StixRevoked;

import java.io.Serializable;

public interface RelationshipObject extends Serializable,
                                            StixCommonProperties,
                                            StixCustomProperties,
                                            StixLabels,
                                            StixModified,
                                            StixRevoked {

}
