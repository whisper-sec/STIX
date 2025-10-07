package security.whisper.javastix.coo.objects;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import security.whisper.javastix.common.StixInstant;
import security.whisper.javastix.coo.CyberObservableObject;
import security.whisper.javastix.coo.types.MimePartTypeObj;
import security.whisper.javastix.validation.constraints.businessrule.BusinessRule;
import security.whisper.javastix.validation.constraints.defaulttypevalue.DefaultTypeValue;
import security.whisper.javastix.validation.groups.DefaultValuesProcessor;
import org.immutables.serial.Serial;
import org.immutables.value.Value;

import javax.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * The Email Message Object represents an instance of an email message.
 *
 */
@Value.Immutable @Serial.Version(1L)
@DefaultTypeValue(value = "email-message", groups = {DefaultValuesProcessor.class})
@Value.Style(typeAbstract="*Coo", typeImmutable="*", validationMethod = Value.Style.ValidationMethod.NONE, additionalJsonAnnotations = {JsonTypeName.class}, depluralize = true)
@JsonTypeName("email-message")
@JsonSerialize(as = EmailMessage.class) @JsonDeserialize(builder = EmailMessage.Builder.class)
@JsonPropertyOrder({ "type", "extensions", "is_multipart", "date", "content_type", "from_ref", "sender_ref", "to_refs", "cc_refs", "bcc_refs", "subject",
        "received_lines", "additional_header_fields", "body", "body_multipart", "raw_email_ref" })
@JsonInclude(value = NON_EMPTY, content= NON_EMPTY)
@BusinessRule(ifExp = "isMultipart() == true", thenExp = "getBody().isPresent() == false", errorMessage = "Body cannot be used if isMultipart equals true")
@BusinessRule(ifExp = "isMultipart() == false", thenExp = "getBodyMultipart().isEmpty() == true", errorMessage = "Body_Multipart cannot be used if isMultipart equals false")
public interface EmailMessageCoo extends CyberObservableObject {

    @JsonProperty("is_multipart")
    @JsonPropertyDescription("Indicates whether the email body contains multiple MIME parts.")
    @NotNull
    Boolean isMultipart();

    @JsonProperty("date")
    @JsonPropertyDescription("Specifies the date/time that the email message was sent.")
    Optional<StixInstant> getDate();

    @JsonProperty("content_type")
    @JsonPropertyDescription("Specifies the value of the 'Content-Type' header of the email message.")
    Optional<String> getContentType();

    @JsonProperty("from_ref")
    @JsonPropertyDescription("Specifies the value of the 'From:' header of the email message.")
    Optional<String> getFromRef();

    @JsonProperty("sender_ref")
    @JsonPropertyDescription("Specifies the value of the 'From' field of the email message")
    Optional<String> getSenderRef();

    @JsonProperty("to_refs")
    @JsonPropertyDescription("Specifies the mailboxes that are 'To:' recipients of the email message")
    default Set<String> getToRefs() {
        return null;
    }

    @JsonProperty("cc_refs")
    @JsonPropertyDescription("Specifies the mailboxes that are 'CC:' recipients of the email message")
    default Set<String> getCcRefs() {
        return null;
    }

    @JsonProperty("bcc_refs")
    @JsonPropertyDescription("Specifies the mailboxes that are 'BCC:' recipients of the email message.")
    default Set<String> getBccRefs() {
        return null;
    }

    @JsonProperty("subject")
    @JsonPropertyDescription("Specifies the subject of the email message.")
    default Optional<String> getSubject() {
        return Optional.empty();
    }

    @JsonProperty("received_lines")
    @JsonPropertyDescription("Specifies one or more Received header fields that may be included in the email headers.")
    default Set<String> getReceivedLines() {
        return null;
    }

    //@TODO Should become a Multi-Map in the future https://github.com/oasis-tcs/cti-stix2/issues/138
    @JsonProperty("additional_header_fields")
    @JsonPropertyDescription("Specifies any other header fields (except for date, received_lines, content_type, from_ref, sender_ref, to_refs, cc_refs, bcc_refs, and subject) found in the email message, as a dictionary.")
    default Map<String, String> getAdditionalHeaderFields() {
        return null;
    }

    @JsonProperty("body")
    @JsonPropertyDescription("Specifies a string containing the email body.")
    default Optional<String> getBody() {
        return Optional.empty();
    }

    @JsonProperty("body_multipart")
    @JsonPropertyDescription("Specifies a list of the MIME parts that make up the email body.")
    default Set<MimePartTypeObj> getBodyMultipart() {
        return null;
    }

    @JsonProperty("raw_email_ref")
    @JsonPropertyDescription("Specifies the raw binary contents of the email message, including both the headers and body, as a reference to an Artifact Object.")
    default Optional<String> getRawEmailRef() {
        return Optional.empty();
    }

    /**
     * Deterministically generates the ID for this email message based on its subject, from, date, and content.
     */
    @Override
    @Value.Derived
    default String getId() {
        StringBuilder identifier = new StringBuilder();

        if (getSubject().isPresent()) {
            identifier.append(getSubject().get());
        }

        if (getFromRef().isPresent()) {
            if (identifier.length() > 0) identifier.append(":");
            identifier.append(getFromRef().get());
        }

        if (getDate().isPresent()) {
            if (identifier.length() > 0) identifier.append(":");
            identifier.append(getDate().get().toString());
        }

        if (identifier.length() == 0) {
            // Fallback to body or multipart status
            if (getBody().isPresent()) {
                identifier.append(getBody().get().substring(0, Math.min(100, getBody().get().length())));
            } else {
                identifier.append("email:").append(isMultipart());
            }
        }

        return "email-message--" + UUID.nameUUIDFromBytes(identifier.toString().getBytes(StandardCharsets.UTF_8));
    }

}
