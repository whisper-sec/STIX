package security.whisper.javastix.taxii.internal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import security.whisper.javastix.helpers.StixSpecVersion;
import security.whisper.javastix.json.StixParsers;
import security.whisper.javastix.taxii.TaxiiClient;
import security.whisper.javastix.taxii.TaxiiCursor;
import security.whisper.javastix.taxii.TaxiiFilter;
import security.whisper.javastix.taxii.TaxiiPage;
import security.whisper.javastix.taxii.auth.TaxiiCredentials;
import security.whisper.javastix.taxii.exception.TaxiiAuthException;
import security.whisper.javastix.taxii.exception.TaxiiException;
import security.whisper.javastix.taxii.exception.TaxiiNotFoundException;
import security.whisper.javastix.taxii.exception.TaxiiProtocolException;
import security.whisper.javastix.taxii.exception.TaxiiServerException;
import security.whisper.javastix.taxii.exception.TaxiiTransportException;
import security.whisper.javastix.taxii.http.TaxiiHttpClient;
import security.whisper.javastix.taxii.http.TaxiiHttpRequest;
import security.whisper.javastix.taxii.http.TaxiiHttpResponse;
import security.whisper.javastix.taxii.model.ApiRoot;
import security.whisper.javastix.taxii.model.Collection;
import security.whisper.javastix.taxii.model.Discovery;
import security.whisper.javastix.taxii.model.ErrorMessage;
import security.whisper.javastix.taxii.model.Manifest;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.UUID;

/**
 * Package-private orchestrator: composes the HTTP transport with the
 * shared Jackson mapper, builds URLs, and maps responses into the public
 * TAXII model types and {@link TaxiiPage}.
 */
public final class TaxiiClientImpl implements TaxiiClient {

    private static final String TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1";

    private final URI base;
    private final TaxiiCredentials credentials;
    private final TaxiiHttpClient http;
    private final ObjectMapper mapper;

    public TaxiiClientImpl(String baseUrl, TaxiiCredentials credentials, TaxiiHttpClient http) {
        Objects.requireNonNull(baseUrl, "baseUrl");
        this.base = URI.create(normalizeTrailing(baseUrl));
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.http = Objects.requireNonNull(http, "http");
        this.mapper = StixParsers.getJsonMapper();
    }

    @Override
    public Discovery discover() {
        TaxiiHttpResponse resp = send(resolve("taxii2/"));
        return parse(resp, Discovery.class);
    }

    @Override
    public ApiRoot apiRoot(String apiRootPath) {
        Objects.requireNonNull(apiRootPath, "apiRootPath");
        String path = stripLeading(normalizeTrailing(apiRootPath));
        TaxiiHttpResponse resp = send(resolve(path));
        ApiRoot raw = parse(resp, ApiRoot.class);
        return raw.withPath(path);
    }

    @Override
    public List<Collection> collections(ApiRoot apiRoot) {
        requireApiRootPath(apiRoot);
        TaxiiHttpResponse resp = send(resolve(apiRoot.getPath() + "collections/"));
        return parseCollections(resp);
    }

    @Override
    public Collection collection(ApiRoot apiRoot, String collectionId) {
        requireApiRootPath(apiRoot);
        Objects.requireNonNull(collectionId, "collectionId");
        URI uri = resolve(apiRoot.getPath() + "collections/" + collectionId + "/");
        TaxiiHttpResponse resp = send(uri);
        return parse(resp, Collection.class);
    }

    @Override
    public TaxiiPage objects(ApiRoot apiRoot, Collection collection,
                             TaxiiCursor cursor, TaxiiFilter filter) {
        requireApiRootPath(apiRoot);
        Objects.requireNonNull(collection, "collection");
        Objects.requireNonNull(cursor, "cursor");
        Objects.requireNonNull(filter, "filter");
        String path = apiRoot.getPath() + "collections/" + collection.getId() + "/objects/";
        URI uri = resolve(path, cursor, filter);
        return toPage(send(uri));
    }

    @Override
    public TaxiiPage objects(URI absoluteUrl) {
        Objects.requireNonNull(absoluteUrl, "absoluteUrl");
        if (!absoluteUrl.isAbsolute()) {
            throw new IllegalArgumentException(
                    "absoluteUrl must be absolute: " + absoluteUrl);
        }
        return toPage(send(absoluteUrl));
    }

    @Override
    public Manifest manifest(ApiRoot apiRoot, Collection collection,
                             TaxiiCursor cursor, TaxiiFilter filter) {
        requireApiRootPath(apiRoot);
        Objects.requireNonNull(collection, "collection");
        Objects.requireNonNull(cursor, "cursor");
        Objects.requireNonNull(filter, "filter");
        String path = apiRoot.getPath() + "collections/" + collection.getId() + "/manifest/";
        return parse(send(resolve(path, cursor, filter)), Manifest.class);
    }

    @Override
    public void close() {
        // JDK adapter holds no closeable resources; custom adapters may.
    }

    // --------------------------------------------------------------------
    // HTTP and parsing helpers
    // --------------------------------------------------------------------

    private TaxiiHttpResponse send(URI uri) {
        TaxiiHttpRequest.Builder b = TaxiiHttpRequest.builder()
                .method("GET")
                .uri(uri)
                .header("Accept", TAXII_MEDIA_TYPE);
        String auth = credentials.authorizationHeader();
        if (auth != null) {
            b.header("Authorization", auth);
        }
        TaxiiHttpResponse resp;
        try {
            resp = http.send(b.build());
        } catch (IOException ioe) {
            throw new TaxiiTransportException("TAXII transport failure: " + uri, ioe);
        }
        checkStatus(resp, uri);
        checkContentType(resp);
        return resp;
    }

    private void checkStatus(TaxiiHttpResponse resp, URI uri) {
        int code = resp.statusCode();
        if (code >= 200 && code < 300) {
            return;
        }
        String detail = describeError(resp);
        String message = "TAXII " + code + " for " + uri + (detail.isEmpty() ? "" : " - " + detail);
        if (code == 401 || code == 403) {
            throw new TaxiiAuthException(message, code);
        }
        if (code == 404) {
            throw new TaxiiNotFoundException(message);
        }
        if (code >= 500) {
            throw new TaxiiServerException(message, code);
        }
        throw new TaxiiException(message, code);
    }

    private String describeError(TaxiiHttpResponse resp) {
        if (resp.body() == null || resp.body().isEmpty()) {
            return "";
        }
        try {
            ErrorMessage err = mapper.readValue(resp.body(), ErrorMessage.class);
            StringBuilder sb = new StringBuilder();
            if (err.getTitle() != null) {
                sb.append(err.getTitle());
            }
            err.getDescription().ifPresent(d -> {
                if (sb.length() > 0) sb.append(": ");
                sb.append(d);
            });
            return sb.toString();
        } catch (IOException ignored) {
            return "";
        }
    }

    private void checkContentType(TaxiiHttpResponse resp) {
        String ct = resp.firstHeader("Content-Type").orElse(null);
        if (ct == null) {
            return; // some servers omit it on 204 / empty payloads
        }
        String lower = ct.toLowerCase(java.util.Locale.ROOT);
        if (!lower.contains("taxii+json") && !lower.contains("stix+json")
                && !lower.contains("application/json")) {
            throw new TaxiiProtocolException(
                    "Unexpected Content-Type for TAXII response: " + ct);
        }
    }

    private <T> T parse(TaxiiHttpResponse resp, Class<T> type) {
        try {
            return mapper.readValue(resp.body(), type);
        } catch (IOException e) {
            throw new TaxiiProtocolException(
                    "Failed to parse TAXII " + type.getSimpleName() + " payload", e);
        }
    }

    private List<Collection> parseCollections(TaxiiHttpResponse resp) {
        try {
            JsonNode root = mapper.readTree(resp.body());
            JsonNode arr = root.get("collections");
            if (arr == null || arr.isNull()) {
                return List.of();
            }
            return mapper.convertValue(arr, new TypeReference<List<Collection>>() {});
        } catch (IOException e) {
            throw new TaxiiProtocolException(
                    "Failed to parse TAXII collections payload", e);
        }
    }

    private TaxiiPage toPage(TaxiiHttpResponse resp) {
        String body = resp.body();
        boolean more = false;
        String nextEnvelope = null;
        ArrayNode objectsArr;
        try {
            JsonNode root = mapper.readTree(body);
            JsonNode moreNode = root.get("more");
            if (moreNode != null && moreNode.isBoolean()) {
                more = moreNode.asBoolean();
            }
            JsonNode nextNode = root.get("next");
            if (nextNode != null && !nextNode.isNull()) {
                nextEnvelope = nextNode.asText();
            }
            JsonNode objsNode = root.get("objects");
            objectsArr = (objsNode != null && objsNode.isArray())
                    ? (ArrayNode) objsNode
                    : mapper.createArrayNode();
        } catch (IOException e) {
            throw new TaxiiProtocolException("Failed to parse TAXII envelope", e);
        }

        Instant first = parseHttpInstant(resp, "X-TAXII-Date-Added-First");
        Instant last = parseHttpInstant(resp, "X-TAXII-Date-Added-Last");

        TaxiiCursor next;
        if (more) {
            if (last == null && nextEnvelope == null) {
                throw new TaxiiProtocolException(
                        "Server signalled more=true but provided no pagination state");
            }
            next = TaxiiCursor.begin();
            if (last != null) {
                next = next.withAddedAfter(last);
            }
            if (nextEnvelope != null) {
                next = next.withNext(nextEnvelope);
            }
        } else {
            next = TaxiiCursor.begin();
            if (last != null) {
                next = next.withAddedAfter(last);
            }
        }

        String bundleJson = wrapAsStixBundle(objectsArr);
        return new TaxiiPage(bundleJson, more, next, first, last);
    }

    private String wrapAsStixBundle(ArrayNode objectsArr) {
        // TAXII envelopes are NOT STIX bundles (spec §3.6.1), but we expose
        // the page body in STIX-bundle form so callers can hand it directly
        // to StixParsers.parseBundle (per the v1.4.0 design contract).
        ObjectNode bundle = mapper.createObjectNode();
        bundle.put("type", "bundle");
        bundle.put("id", "bundle--" + UUID.randomUUID());
        bundle.put("spec_version", StixSpecVersion.SPECVERSION);
        bundle.set("objects", objectsArr);
        try {
            return mapper.writeValueAsString(bundle);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new TaxiiProtocolException(
                    "Failed to wrap TAXII envelope as STIX bundle", e);
        }
    }

    private Instant parseHttpInstant(TaxiiHttpResponse resp, String headerName) {
        String value = resp.firstHeader(headerName).orElse(null);
        if (value == null) {
            return null;
        }
        try {
            return DateTimeFormatter.ISO_INSTANT.parse(value, Instant::from);
        } catch (DateTimeParseException dtpe) {
            try {
                return DateTimeFormatter.ISO_OFFSET_DATE_TIME.parse(value, Instant::from);
            } catch (DateTimeParseException dtpe2) {
                throw new TaxiiProtocolException(
                        "Cannot parse " + headerName + ": " + value, dtpe2);
            }
        }
    }

    // --------------------------------------------------------------------
    // URL construction
    // --------------------------------------------------------------------

    private URI resolve(String relativePath) {
        return base.resolve(relativePath);
    }

    private URI resolve(String relativePath, TaxiiCursor cursor, TaxiiFilter filter) {
        StringJoiner q = new StringJoiner("&");
        cursor.getAddedAfter().ifPresent(t ->
                q.add("added_after=" + enc(t.toString())));
        cursor.getNext().ifPresent(n ->
                q.add("next=" + enc(n)));
        if (!filter.getTypes().isEmpty()) {
            q.add("match[type]=" + enc(String.join(",", filter.getTypes())));
        }
        if (!filter.getIds().isEmpty()) {
            q.add("match[id]=" + enc(String.join(",", filter.getIds())));
        }
        if (!filter.getVersions().isEmpty()) {
            q.add("match[version]=" + enc(String.join(",", filter.getVersions())));
        }
        if (!filter.getSpecVersions().isEmpty()) {
            q.add("match[spec_version]=" + enc(String.join(",", filter.getSpecVersions())));
        }
        filter.getLimit().ifPresent(l -> q.add("limit=" + l));

        URI base = resolve(relativePath);
        if (q.length() == 0) {
            return base;
        }
        String sep = base.getRawQuery() == null ? "?" : "&";
        return URI.create(base + sep + q);
    }

    private static void requireApiRootPath(ApiRoot apiRoot) {
        Objects.requireNonNull(apiRoot, "apiRoot");
        if (apiRoot.getPath() == null || apiRoot.getPath().isEmpty()) {
            throw new IllegalArgumentException(
                    "ApiRoot must carry a path - obtain it via TaxiiClient.apiRoot(String) "
                            + "or via Discovery.getApiRoots() resolved against the base URL");
        }
    }

    private static String normalizeTrailing(String url) {
        return url.endsWith("/") ? url : url + "/";
    }

    private static String stripLeading(String path) {
        int i = 0;
        while (i < path.length() && path.charAt(i) == '/') {
            i++;
        }
        return path.substring(i);
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
