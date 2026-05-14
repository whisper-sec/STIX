package security.whisper.javastix.taxii;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Filter parameters for {@code GET /{api-root}/collections/{id}/objects/}
 * and the equivalent manifest endpoint. All fields are optional; the
 * filter is sent as query parameters per the TAXII 2.1 spec.
 *
 * <p>Per spec §3.4, multi-valued match parameters are encoded as a single
 * comma-separated list (e.g. {@code match[type]=indicator,malware}).
 */
public final class TaxiiFilter {

    private final List<String> types;
    private final List<String> ids;
    private final List<String> versions;
    private final List<String> specVersions;
    private final Integer limit;

    private TaxiiFilter(Builder b) {
        this.types = Collections.unmodifiableList(new ArrayList<>(b.types));
        this.ids = Collections.unmodifiableList(new ArrayList<>(b.ids));
        this.versions = Collections.unmodifiableList(new ArrayList<>(b.versions));
        this.specVersions = Collections.unmodifiableList(new ArrayList<>(b.specVersions));
        this.limit = b.limit;
    }

    public List<String> getTypes() { return types; }
    public List<String> getIds() { return ids; }
    public List<String> getVersions() { return versions; }
    public List<String> getSpecVersions() { return specVersions; }
    public Optional<Integer> getLimit() { return Optional.ofNullable(limit); }

    public boolean isEmpty() {
        return types.isEmpty() && ids.isEmpty()
                && versions.isEmpty() && specVersions.isEmpty()
                && limit == null;
    }

    public static TaxiiFilter none() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final List<String> types = new ArrayList<>();
        private final List<String> ids = new ArrayList<>();
        private final List<String> versions = new ArrayList<>();
        private final List<String> specVersions = new ArrayList<>();
        private Integer limit;

        public Builder addType(String type) {
            this.types.add(Objects.requireNonNull(type, "type"));
            return this;
        }

        public Builder addId(String id) {
            this.ids.add(Objects.requireNonNull(id, "id"));
            return this;
        }

        public Builder addVersion(String version) {
            this.versions.add(Objects.requireNonNull(version, "version"));
            return this;
        }

        public Builder addSpecVersion(String specVersion) {
            this.specVersions.add(Objects.requireNonNull(specVersion, "specVersion"));
            return this;
        }

        public Builder limit(int limit) {
            if (limit <= 0) {
                throw new IllegalArgumentException("limit must be positive");
            }
            this.limit = limit;
            return this;
        }

        public TaxiiFilter build() {
            return new TaxiiFilter(this);
        }
    }
}
