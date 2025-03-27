package com.noctisnet.stix.coo.extension;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.noctisnet.stix.common.StixCustomProperties;
import com.noctisnet.stix.validation.GenericValidation;


/**
 * Interface to tag Cyber Observable Extension classes
 *
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type", include = JsonTypeInfo.As.EXISTING_PROPERTY)
public interface CyberObservableExtension extends
        CyberObservableExtensionCommonProperties,
        GenericValidation,
        StixCustomProperties {

}
