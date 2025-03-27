package com.noctisnet.stix.sro;

import com.noctisnet.stix.common.StixCommonProperties;
import com.noctisnet.stix.common.StixCustomProperties;
import com.noctisnet.stix.common.StixLabels;
import com.noctisnet.stix.common.StixModified;
import com.noctisnet.stix.common.StixRevoked;

import java.io.Serializable;

public interface RelationshipObject extends Serializable,
                                            StixCommonProperties,
                                            StixCustomProperties,
                                            StixLabels,
                                            StixModified,
                                            StixRevoked {

}
