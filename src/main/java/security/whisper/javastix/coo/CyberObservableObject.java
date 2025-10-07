package security.whisper.javastix.coo;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.validation.constraints.coo.allowedparents.ValidateExtensions;

import java.io.Serializable;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type", include = JsonTypeInfo.As.EXISTING_PROPERTY)
@ValidateExtensions
public interface CyberObservableObject extends Serializable,
        CyberObservableObjectCommonProperties,
        StixCustomProperties,
        BundleableObject {

}
