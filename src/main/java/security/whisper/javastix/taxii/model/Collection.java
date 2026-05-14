package security.whisper.javastix.taxii.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A single TAXII collection's metadata as returned by
 * {@code GET /{api-root}/collections/{id}/}.
 *
 * <p>Note: the type intentionally shadows {@code java.util.Collection} in
 * source files that import it. The TAXII spec name is "Collection", so we
 * keep that for fidelity; consumers can alias with a static import or use
 * the FQN when both types are in scope.
 *
 * <p>See OASIS TAXII 2.1, §5.2.
 */
public final class Collection {

    private final String id;
    private final String title;
    private final String description;
    private final String alias;
    private final boolean canRead;
    private final boolean canWrite;
    private final List<String> mediaTypes;

    @JsonCreator
    public Collection(
            @JsonProperty("id") String id,
            @JsonProperty("title") String title,
            @JsonProperty("description") String description,
            @JsonProperty("alias") String alias,
            @JsonProperty("can_read") Boolean canRead,
            @JsonProperty("can_write") Boolean canWrite,
            @JsonProperty("media_types") List<String> mediaTypes) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.alias = alias;
        this.canRead = canRead != null && canRead;
        this.canWrite = canWrite != null && canWrite;
        this.mediaTypes = mediaTypes == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(mediaTypes);
    }

    public String getId() { return id; }
    public String getTitle() { return title; }
    public Optional<String> getDescription() { return Optional.ofNullable(description); }
    public Optional<String> getAlias() { return Optional.ofNullable(alias); }
    public boolean canRead() { return canRead; }
    public boolean canWrite() { return canWrite; }
    public List<String> getMediaTypes() { return mediaTypes; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Collection)) return false;
        Collection that = (Collection) o;
        return canRead == that.canRead
                && canWrite == that.canWrite
                && Objects.equals(id, that.id)
                && Objects.equals(title, that.title)
                && Objects.equals(description, that.description)
                && Objects.equals(alias, that.alias)
                && Objects.equals(mediaTypes, that.mediaTypes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, title, description, alias, canRead, canWrite, mediaTypes);
    }
}
