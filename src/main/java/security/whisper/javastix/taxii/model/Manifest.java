package security.whisper.javastix.taxii.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Envelope returned by {@code GET /{api-root}/collections/{id}/manifest/}.
 * Carries per-object timestamps so a consumer can decide which STIX
 * objects to fetch in detail.
 *
 * <p>See OASIS TAXII 2.1, §5.4.
 */
public final class Manifest {

    private final boolean more;
    private final String next;
    private final List<ManifestRecord> objects;

    @JsonCreator
    public Manifest(
            @JsonProperty("more") Boolean more,
            @JsonProperty("next") String next,
            @JsonProperty("objects") List<ManifestRecord> objects) {
        this.more = more != null && more;
        this.next = next;
        this.objects = objects == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(objects);
    }

    public boolean isMore() { return more; }
    public Optional<String> getNext() { return Optional.ofNullable(next); }
    public List<ManifestRecord> getObjects() { return objects; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Manifest)) return false;
        Manifest that = (Manifest) o;
        return more == that.more
                && Objects.equals(next, that.next)
                && Objects.equals(objects, that.objects);
    }

    @Override
    public int hashCode() {
        return Objects.hash(more, next, objects);
    }
}
