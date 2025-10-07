package security.whisper.javastix.coo.extension;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import security.whisper.javastix.common.StixCustomProperties;
import security.whisper.javastix.validation.GenericValidation;


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
