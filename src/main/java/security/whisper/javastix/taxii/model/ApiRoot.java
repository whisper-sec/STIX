package security.whisper.javastix.taxii.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Metadata returned by {@code GET /{api-root}/}.
 *
 * <p>The {@link #getPath()} property is not part of the TAXII response
 * body - it is set by the client to remember which path the API root was
 * fetched from, so subsequent collection / object calls know which URL to
 * construct.
 *
 * <p>See OASIS TAXII 2.1, §4.2.
 */
public final class ApiRoot {

    private final String path;
    private final String title;
    private final String description;
    private final List<String> versions;
    private final Long maxContentLength;

    @JsonCreator
    public ApiRoot(
            @JsonProperty("title") String title,
            @JsonProperty("description") String description,
            @JsonProperty("versions") List<String> versions,
            @JsonProperty("max_content_length") Long maxContentLength) {
        this(null, title, description, versions, maxContentLength);
    }

    public ApiRoot(String path, String title, String description,
                   List<String> versions, Long maxContentLength) {
        this.path = path;
        this.title = title;
        this.description = description;
        this.versions = versions == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(versions);
        this.maxContentLength = maxContentLength;
    }

    /**
     * Returns a copy of this API root with its path set. Used by the client
     * after fetching {@code GET /{api-root}/} so callers can pass the value
     * back into subsequent collection lookups.
     */
    public ApiRoot withPath(String path) {
        return new ApiRoot(path, title, description, versions, maxContentLength);
    }

    public String getPath() { return path; }
    public String getTitle() { return title; }
    public Optional<String> getDescription() { return Optional.ofNullable(description); }
    public List<String> getVersions() { return versions; }
    public Optional<Long> getMaxContentLength() { return Optional.ofNullable(maxContentLength); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ApiRoot)) return false;
        ApiRoot that = (ApiRoot) o;
        return Objects.equals(path, that.path)
                && Objects.equals(title, that.title)
                && Objects.equals(description, that.description)
                && Objects.equals(versions, that.versions)
                && Objects.equals(maxContentLength, that.maxContentLength);
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, title, description, versions, maxContentLength);
    }
}
