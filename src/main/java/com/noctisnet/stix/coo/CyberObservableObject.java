package com.noctisnet.stix.coo;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.noctisnet.stix.common.StixCustomProperties;
import com.noctisnet.stix.validation.constraints.coo.allowedparents.ValidateExtensions;

import java.io.Serializable;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type", include = JsonTypeInfo.As.EXISTING_PROPERTY)
@ValidateExtensions
public interface CyberObservableObject extends Serializable,
        CyberObservableObjectCommonProperties,
        StixCustomProperties {

}
