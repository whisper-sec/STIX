package security.whisper.javastix.taxii.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Server discovery response - {@code GET /taxii2/}. Lists the API roots
 * the server exposes plus optional contact metadata.
 *
 * <p>See OASIS TAXII 2.1, §4.1.
 */
public final class Discovery {

    private final String title;
    private final String description;
    private final String contact;
    private final String defaultApiRoot;
    private final List<String> apiRoots;

    @JsonCreator
    public Discovery(
            @JsonProperty("title") String title,
            @JsonProperty("description") String description,
            @JsonProperty("contact") String contact,
            @JsonProperty("default") String defaultApiRoot,
            @JsonProperty("api_roots") List<String> apiRoots) {
        this.title = title;
        this.description = description;
        this.contact = contact;
        this.defaultApiRoot = defaultApiRoot;
        this.apiRoots = apiRoots == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(apiRoots);
    }

    public String getTitle() { return title; }
    public Optional<String> getDescription() { return Optional.ofNullable(description); }
    public Optional<String> getContact() { return Optional.ofNullable(contact); }
    public Optional<String> getDefaultApiRoot() { return Optional.ofNullable(defaultApiRoot); }
    public List<String> getApiRoots() { return apiRoots; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Discovery)) return false;
        Discovery that = (Discovery) o;
        return Objects.equals(title, that.title)
                && Objects.equals(description, that.description)
                && Objects.equals(contact, that.contact)
                && Objects.equals(defaultApiRoot, that.defaultApiRoot)
                && Objects.equals(apiRoots, that.apiRoots);
    }

    @Override
    public int hashCode() {
        return Objects.hash(title, description, contact, defaultApiRoot, apiRoots);
    }
}
