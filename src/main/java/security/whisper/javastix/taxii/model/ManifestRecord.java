package security.whisper.javastix.taxii.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * One record from a TAXII manifest envelope - describes when a given STIX
 * object was added to the collection and which media type it was uploaded
 * as.
 *
 * <p>See OASIS TAXII 2.1, §5.4.
 */
public final class ManifestRecord {

    private final String id;
    private final Instant dateAdded;
    private final String version;
    private final String mediaType;

    @JsonCreator
    public ManifestRecord(
            @JsonProperty("id") String id,
            @JsonProperty("date_added") Instant dateAdded,
            @JsonProperty("version") String version,
            @JsonProperty("media_type") String mediaType) {
        this.id = id;
        this.dateAdded = dateAdded;
        this.version = version;
        this.mediaType = mediaType;
    }

    public String getId() { return id; }
    public Instant getDateAdded() { return dateAdded; }
    public String getVersion() { return version; }
    public Optional<String> getMediaType() { return Optional.ofNullable(mediaType); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ManifestRecord)) return false;
        ManifestRecord that = (ManifestRecord) o;
        return Objects.equals(id, that.id)
                && Objects.equals(dateAdded, that.dateAdded)
                && Objects.equals(version, that.version)
                && Objects.equals(mediaType, that.mediaType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, dateAdded, version, mediaType);
    }
}
