package security.whisper.javastix.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Validates JSON against the official OASIS STIX 2.1 JSON schemas
 * (github.com/oasis-open/cti-stix2-json-schemas), vendored under
 * {@code src/test/resources/stix/oasis/schemas}. The schemas reference each other by
 * their published {@code $id}, which is mapped onto the classpath copy so that the
 * tests never touch the network.
 */
final class OasisSchemas {

    private static final String PUBLISHED_PREFIX =
            "http://raw.githubusercontent.com/oasis-open/cti-stix2-json-schemas/stix2.1/schemas/";
    private static final String CLASSPATH_PREFIX = "classpath:stix/oasis/schemas/";

    private static final JsonSchemaFactory FACTORY = JsonSchemaFactory.getInstance(
            SpecVersion.VersionFlag.V202012,
            builder -> builder.schemaMappers(m -> m.mapPrefix(PUBLISHED_PREFIX, CLASSPATH_PREFIX)));

    private static final Set<String> SDOS = Set.of("attack-pattern", "campaign", "course-of-action",
            "grouping", "identity", "incident", "indicator", "infrastructure", "intrusion-set", "location",
            "malware", "malware-analysis", "note", "observed-data", "opinion", "report", "threat-actor",
            "tool", "vulnerability");
    private static final Set<String> SROS = Set.of("relationship", "sighting");
    private static final Set<String> SCOS = Set.of("artifact", "autonomous-system", "directory",
            "domain-name", "email-addr", "email-message", "file", "ipv4-addr", "ipv6-addr", "mac-addr",
            "mutex", "network-traffic", "process", "software", "url", "user-account",
            "windows-registry-key", "x509-certificate");
    private static final Set<String> COMMON = Set.of("bundle", "marking-definition", "language-content",
            "extension-definition");

    private static final Map<String, JsonSchema> CACHE = new ConcurrentHashMap<>();

    private OasisSchemas() {
    }

    /** True when the OASIS schema set has a schema for this STIX type. */
    static boolean hasSchemaFor(String type) {
        return SDOS.contains(type) || SROS.contains(type) || SCOS.contains(type) || COMMON.contains(type);
    }

    /**
     * Validates a STIX object or bundle against the schema for its {@code type}.
     *
     * @return the violations, empty when the JSON is valid
     */
    static Set<String> violations(JsonNode json) {
        String type = json.path("type").asText();
        JsonSchema schema = CACHE.computeIfAbsent(type, OasisSchemas::load);
        return schema.validate(json).stream()
                .map(ValidationMessage::getMessage)
                .collect(Collectors.toCollection(java.util.TreeSet::new));
    }

    private static JsonSchema load(String type) {
        String dir;
        if (SDOS.contains(type)) {
            dir = "sdos/";
        } else if (SROS.contains(type)) {
            dir = "sros/";
        } else if (SCOS.contains(type)) {
            dir = "observables/";
        } else if (COMMON.contains(type)) {
            dir = "common/";
        } else {
            throw new IllegalArgumentException("No OASIS schema for STIX type: " + type);
        }
        return FACTORY.getSchema(SchemaLocation.of(CLASSPATH_PREFIX + dir + type + ".json"));
    }
}
