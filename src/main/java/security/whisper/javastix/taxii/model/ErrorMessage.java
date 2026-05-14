package security.whisper.javastix.taxii.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * TAXII error response body returned by servers on 4xx / 5xx replies.
 *
 * <p>See OASIS TAXII 2.1, §1.6.7.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class ErrorMessage {

    private final String title;
    private final String description;
    private final String errorId;
    private final String errorCode;
    private final String httpStatus;
    private final String externalDetails;
    private final Map<String, String> details;

    @JsonCreator
    public ErrorMessage(
            @JsonProperty("title") String title,
            @JsonProperty("description") String description,
            @JsonProperty("error_id") String errorId,
            @JsonProperty("error_code") String errorCode,
            @JsonProperty("http_status") String httpStatus,
            @JsonProperty("external_details") String externalDetails,
            @JsonProperty("details") Map<String, String> details) {
        this.title = title;
        this.description = description;
        this.errorId = errorId;
        this.errorCode = errorCode;
        this.httpStatus = httpStatus;
        this.externalDetails = externalDetails;
        this.details = details == null
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(details);
    }

    public String getTitle() { return title; }
    public Optional<String> getDescription() { return Optional.ofNullable(description); }
    public Optional<String> getErrorId() { return Optional.ofNullable(errorId); }
    public Optional<String> getErrorCode() { return Optional.ofNullable(errorCode); }
    public Optional<String> getHttpStatus() { return Optional.ofNullable(httpStatus); }
    public Optional<String> getExternalDetails() { return Optional.ofNullable(externalDetails); }
    public Map<String, String> getDetails() { return details; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ErrorMessage)) return false;
        ErrorMessage that = (ErrorMessage) o;
        return Objects.equals(title, that.title)
                && Objects.equals(description, that.description)
                && Objects.equals(errorId, that.errorId)
                && Objects.equals(errorCode, that.errorCode)
                && Objects.equals(httpStatus, that.httpStatus)
                && Objects.equals(externalDetails, that.externalDetails)
                && Objects.equals(details, that.details);
    }

    @Override
    public int hashCode() {
        return Objects.hash(title, description, errorId, errorCode, httpStatus, externalDetails, details);
    }
}
