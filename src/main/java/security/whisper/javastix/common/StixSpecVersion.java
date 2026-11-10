package security.whisper.javastix.common;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import org.immutables.value.Value;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * The {@code spec_version} common property.
 * <p>
 * STIX 2.1 (section 3.2) makes {@code spec_version} REQUIRED on every SDO, SRO, Language Content,
 * Marking Definition and Extension Definition, and OPTIONAL on SCOs; the value MUST be {@code "2.1"}
 * for objects defined by STIX 2.1. The library always emits it, so every object it writes states
 * its version explicitly.
 * <p>
 * On input the property is read as a first-class property (never as a custom property). The OASIS
 * schemas accept {@code "2.0"} and {@code "2.1"}, and so does the library. An object read without
 * the property gets {@code "2.1"}: it is parsed and validated against the STIX 2.1 model, so that is
 * the version it is written back out as.
 */
public interface StixSpecVersion {

    /**
     * The version of the STIX specification used to represent this object.
     *
     * @return the STIX version, {@code "2.1"} unless the object was read with another valid value
     */
    @NotBlank
    @Pattern(regexp = "^2\\.[01]$", message = "spec_version must be \"2.1\" (or \"2.0\" for STIX 2.0 content)")
    @JsonProperty("spec_version")
    @JsonPropertyDescription("The version of the STIX specification used to represent this object.")
    @Value.Default
    default String getSpecVersion() {
        return security.whisper.javastix.helpers.StixSpecVersion.SPECVERSION;
    }

}
