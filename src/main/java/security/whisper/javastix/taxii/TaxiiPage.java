package security.whisper.javastix.taxii;

import com.fasterxml.jackson.databind.JsonNode;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.bundle.BundleableObject;
import security.whisper.javastix.json.StixParserValidationException;
import security.whisper.javastix.json.StixParsers;
import security.whisper.javastix.taxii.exception.TaxiiProtocolException;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * One page of objects from a TAXII collection. The raw response body is
 * available via {@link #bundleJson()} and can be handed to the STIX parser
 * directly, or {@link #bundle()} can be used to parse it lazily through
 * the library's existing entry point.
 *
 * <p>Pagination state - whether more pages exist and what cursor the next
 * request should carry - is exposed through {@link #hasMore()} and
 * {@link #nextCursor()}.
 */
public final class TaxiiPage {

    private final String bundleJson;
    private final boolean more;
    private final TaxiiCursor nextCursor;
    private final Instant dateAddedFirst;
    private final Instant dateAddedLast;

    private volatile BundleObject parsed;

    public TaxiiPage(String bundleJson, boolean more, TaxiiCursor nextCursor,
                     Instant dateAddedFirst, Instant dateAddedLast) {
        this.bundleJson = bundleJson;
        this.more = more;
        this.nextCursor = nextCursor;
        this.dateAddedFirst = dateAddedFirst;
        this.dateAddedLast = dateAddedLast;
    }

    /** Raw TAXII envelope JSON exactly as received from the server. */
    public String bundleJson() { return bundleJson; }

    /** Whether the server indicated additional pages exist. */
    public boolean hasMore() { return more; }

    /** Cursor to pass on the next {@code objects(...)} call. */
    public TaxiiCursor nextCursor() { return nextCursor; }

    public Optional<Instant> dateAddedFirst() { return Optional.ofNullable(dateAddedFirst); }
    public Optional<Instant> dateAddedLast() { return Optional.ofNullable(dateAddedLast); }

    /**
     * Lazily parses the envelope into a {@link BundleObject} via
     * {@link StixParsers#parseBundle(String)}. Subsequent calls return the
     * cached result.
     *
     * <p>The STIX bundle contract requires at least one object, so this
     * method will fail on empty pages. Use {@link #objects()} when iterating
     * pages that may be empty.
     *
     * @throws IOException if the body is not parseable JSON
     * @throws StixParserValidationException if the resulting bundle fails
     *         STIX validation (notably, empty pages will fail this way)
     */
    public BundleObject bundle() throws IOException, StixParserValidationException {
        BundleObject cached = parsed;
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            if (parsed == null) {
                parsed = StixParsers.parseBundle(bundleJson);
            }
            return parsed;
        }
    }

    /**
     * Parses each object in the envelope individually via
     * {@link StixParsers#parseObject(String)}. Safe to call on empty pages,
     * which return an empty list.
     */
    public List<BundleableObject> objects()
            throws IOException, StixParserValidationException {
        JsonNode root = StixParsers.getJsonMapper().readTree(bundleJson);
        JsonNode arr = root.get("objects");
        if (arr == null || !arr.isArray()) {
            throw new TaxiiProtocolException(
                    "Synthetic bundle JSON is missing the 'objects' array");
        }
        List<BundleableObject> out = new ArrayList<>(arr.size());
        for (JsonNode node : arr) {
            out.add(StixParsers.parseObject(node.toString()));
        }
        return out;
    }
}
