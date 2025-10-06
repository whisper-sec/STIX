package com.noctisnet.stix.sdo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.noctisnet.stix.redaction.Redactable;
import com.noctisnet.stix.sdo.DomainObject;
import com.noctisnet.stix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import com.noctisnet.stix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import java.util.Optional;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * location
 * <p>
 * A Location represents a geographic location.
 * This object is part of STIX 2.1 specification.
 */
@Value.Immutable @Serial.Version(1L)
@JsonTypeName("location")
@DefaultTypeValue(value = "location", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Sdo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE,
             additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonSerialize(as = Location.class) @JsonDeserialize(builder = Location.Builder.class)
@JsonPropertyOrder({"type", "id", "created_by_ref", "created", "modified", "revoked", "labels",
        "external_references", "object_marking_refs", "granular_markings",
        "name", "description", "latitude", "longitude", "precision", "region", "country",
        "administrative_area", "city", "street_address", "postal_code"})
@Redactable
public interface LocationSdo extends DomainObject {

    @JsonProperty("name") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A name used to identify the Location.")
    @Redactable
    Optional<String> getName();

    @JsonProperty("description") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("A textual description of the Location.")
    @Redactable
    Optional<String> getDescription();

    @JsonProperty("latitude") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The latitude of the Location in decimal degrees.")
    @Redactable
    Optional<Double> getLatitude();

    @JsonProperty("longitude") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The longitude of the Location in decimal degrees.")
    @Redactable
    Optional<Double> getLongitude();

    @JsonProperty("precision") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("Defines the precision of the coordinates specified by the latitude and longitude properties in meters.")
    @Redactable
    Optional<Double> getPrecision();

    @JsonProperty("region") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The region that this Location describes. Open Vocabulary: region-ov")
    @Redactable
    Optional<String> getRegion();

    @JsonProperty("country") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The country that this Location describes (ISO 3166-1 ALPHA-2 Code).")
    @Redactable
    Optional<String> getCountry();

    @JsonProperty("administrative_area") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The state, province, or other sub-national administrative area that this Location describes.")
    @Redactable
    Optional<String> getAdministrativeArea();

    @JsonProperty("city") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The city that this Location describes.")
    @Redactable
    Optional<String> getCity();

    @JsonProperty("street_address") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The street address that this Location describes.")
    @Redactable
    Optional<String> getStreetAddress();

    @JsonProperty("postal_code") @JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
    @JsonPropertyDescription("The postal code for this Location.")
    @Redactable
    Optional<String> getPostalCode();
}
