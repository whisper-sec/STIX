package com.noctisnet.stix.coo.extension.types;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.coo.extension.CyberObservableExtension;
import com.noctisnet.stix.coo.objects.FileCoo;
import com.noctisnet.stix.coo.types.NtfsAlternateDataStreamObj;
import com.noctisnet.stix.validation.constraints.businessrule.BusinessRule;
import com.noctisnet.stix.validation.constraints.coo.allowedparents.AllowedParents;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * The NTFS file extension specifies a default extension for capturing properties specific to the storage of the file on the NTFS file system.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "ntfs-ext", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Ext", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, passAnnotations = {AllowedParents.class}, depluralize = true)
@JsonSerialize(as = NtfsFileExtenstion.class) @JsonDeserialize(builder = NtfsFileExtenstion.Builder.class)
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
@JsonPropertyOrder({ "sid", "alternate_data_streams" })
@JsonTypeName("ntfs-ext")
@AllowedParents({FileCoo.class})
@BusinessRule(ifExp = "true", thenExp = "getSid().isPresent() == true || getAlternateDataStreams().isEmpty() == false", errorMessage = "NTFS File Extension MUST contain at least one property from this extension")
public interface NtfsFileExtenstionExt extends CyberObservableExtension {

    @JsonProperty("sid")
    @JsonPropertyDescription("Specifies the security ID (SID) value assigned to the file.")
    Optional<String> getSid();

    @JsonProperty("alternate_data_streams")
    @JsonPropertyDescription("Specifies a list of NTFS alternate data streams that exist for the file.")
    default Set<NtfsAlternateDataStreamObj> getAlternateDataStreams() {
        return null;
    }

}
