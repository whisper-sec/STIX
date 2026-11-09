package security.whisper.javastix.conformance;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

/**
 * Structural JSON comparison for round-trip tests. Objects compare by key set and value;
 * arrays compare as multisets, because the library models most STIX lists as sets and does
 * not promise to keep their order. Everything else, timestamps included, must match exactly.
 */
final class JsonEquivalence {

    private JsonEquivalence() {
    }

    /** Lists every difference between {@code expected} and {@code actual}; empty when equivalent. */
    static List<String> differences(JsonNode expected, JsonNode actual) {
        List<String> out = new ArrayList<>();
        compare("$", expected, actual, out);
        return out;
    }

    private static void compare(String path, JsonNode expected, JsonNode actual, List<String> out) {
        if (actual == null || actual.isMissingNode()) {
            out.add(path + ": missing, expected " + expected);
            return;
        }
        if (expected.isObject() && actual.isObject()) {
            TreeSet<String> keys = new TreeSet<>();
            expected.fieldNames().forEachRemaining(keys::add);
            actual.fieldNames().forEachRemaining(keys::add);
            for (String key : keys) {
                if (!actual.has(key)) {
                    out.add(path + "." + key + ": missing, expected " + expected.get(key));
                } else if (!expected.has(key)) {
                    out.add(path + "." + key + ": unexpected " + actual.get(key));
                } else {
                    compare(path + "." + key, expected.get(key), actual.get(key), out);
                }
            }
            return;
        }
        if (expected.isArray() && actual.isArray()) {
            List<JsonNode> remaining = new ArrayList<>();
            actual.forEach(remaining::add);
            for (JsonNode e : expected) {
                Iterator<JsonNode> it = remaining.iterator();
                boolean found = false;
                while (it.hasNext()) {
                    if (differences(e, it.next()).isEmpty()) {
                        it.remove();
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    out.add(path + "[]: no element equivalent to " + e + " in " + actual);
                }
            }
            for (JsonNode extra : remaining) {
                out.add(path + "[]: unexpected element " + extra);
            }
            return;
        }
        if (expected.isNumber() && actual.isNumber()) {
            if (expected.decimalValue().compareTo(actual.decimalValue()) != 0) {
                out.add(path + ": expected " + expected + " but was " + actual);
            }
            return;
        }
        if (!expected.equals(actual)) {
            out.add(path + ": expected " + expected + " but was " + actual);
        }
    }
}
