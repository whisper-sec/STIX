package com.noctisnet.stix.coo.extension.types;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.coo.extension.CyberObservableExtension;
import com.noctisnet.stix.coo.objects.ProcessCoo;
import com.noctisnet.stix.validation.constraints.coo.allowedparents.AllowedParents;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.constraints.vocab.Vocab;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import com.noctisnet.stix.vocabulary.vocabularies.WindowsServiceStartTypes;
import com.noctisnet.stix.vocabulary.vocabularies.WindowsServiceStatuses;
import com.noctisnet.stix.vocabulary.vocabularies.WindowsServiceTypes;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotBlank;
import java.util.Optional;
import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * windows-service-ext
 * <p>
 * The Windows Service extension specifies a default extension for capturing
 * properties specific to Windows services.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "windows-service-ext", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Ext", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, passAnnotations = {AllowedParents.class}, depluralize = true)
@JsonSerialize(as = WindowsServiceExtension.class) @JsonDeserialize(builder = WindowsServiceExtension.Builder.class)
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
@JsonPropertyOrder({ "service_name", "descriptions", "display_name", "group_name", "start_type", "service_dll_refs",
        "service_type", "service_status" })
@JsonTypeName("windows-service-ext")
@AllowedParents({ProcessCoo.class})
public interface WindowsServiceExtensionExt extends CyberObservableExtension {

    @JsonProperty("service_name")
    @JsonPropertyDescription("Specifies the name of the service.")
    @NotBlank
    String getServiceName();

    @JsonProperty("descriptions")
    @JsonPropertyDescription("Specifies the descriptions defined for the service.")
    default Set<String> getDescriptions() {
        return null;
    }

    @JsonProperty("display_name")
    @JsonPropertyDescription("Specifies the displayed name of the service in Windows GUI controls.")
    Optional<String> getDisplayName();

    @JsonProperty("group_name")
    @JsonPropertyDescription("Specifies the name of the load ordering group of which the service is a member.")
    Optional<String> getGroupName();

    @JsonProperty("start_type")
    @JsonPropertyDescription("Specifies the start options defined for the service. windows-service-start-enum")
    Optional<@Vocab(WindowsServiceStartTypes.class) String> getServiceStartType();

    @JsonProperty("service_dll_refs")
    @JsonPropertyDescription("Specifies the DLLs loaded by the service, as a reference to one or more File Objects.")
    default Set<String> getServiceDllRefs() {
        return null;
    }

    @JsonProperty("service_type")
    @JsonPropertyDescription("Specifies the type of the service. windows-service-enum")
    Optional<@Vocab(WindowsServiceTypes.class) String> getServiceType();

    @JsonProperty("service_status")
    @JsonPropertyDescription("Specifies the current status of the service. windows-service-status-enum")
    Optional<@Vocab(WindowsServiceStatuses.class) String> getServiceStatus();

}
