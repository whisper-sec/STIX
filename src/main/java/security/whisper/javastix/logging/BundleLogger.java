package security.whisper.javastix.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.bundle.BundleObject;
import security.whisper.javastix.bundle.BundleableObject;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * Logging utilities for Bundle operations.
 * Provides centralized logging for bundle creation, modification, and serialization.
 *
 * @since 1.3.0
 */
public class BundleLogger {

    private static final Logger logger = LoggerFactory.getLogger(BundleLogger.class);

    /**
     * Private constructor to prevent instantiation.
     */
    private BundleLogger() {
    }

    /**
     * Logs bundle creation.
     *
     * @param bundle The created bundle
     */
    public static void logBundleCreation(BundleObject bundle) {
        if (bundle == null) {
            logger.warn("Attempted to log null bundle creation");
            return;
        }

        logger.info("Created bundle with ID: {} containing {} objects",
            bundle.getId(), bundle.getObjects().size());

        if (logger.isDebugEnabled()) {
            Map<String, Long> typeCounts = bundle.getObjects().stream()
                .collect(Collectors.groupingBy(
                    BundleableObject::getType,
                    Collectors.counting()
                ));

            logger.debug("Bundle object types: {}", typeCounts);
        }
    }

    /**
     * Logs bundle serialization start.
     *
     * @param bundleId The bundle ID being serialized
     * @param objectCount Number of objects in the bundle
     */
    public static void logSerializationStart(String bundleId, int objectCount) {
        logger.debug("Starting serialization of bundle {} with {} objects",
            bundleId, objectCount);
    }

    /**
     * Logs bundle serialization completion.
     *
     * @param bundleId The bundle ID that was serialized
     * @param jsonLength Length of the resulting JSON
     */
    public static void logSerializationComplete(String bundleId, int jsonLength) {
        logger.debug("Completed serialization of bundle {} (JSON length: {} chars)",
            bundleId, jsonLength);
    }

    /**
     * Logs bundle serialization error.
     *
     * @param bundleId The bundle ID that failed to serialize
     * @param error The error that occurred
     */
    public static void logSerializationError(String bundleId, Exception error) {
        logger.error("Failed to serialize bundle {}: {}",
            bundleId, error.getMessage(), error);
    }

    /**
     * Logs bundle deserialization start.
     *
     * @param jsonLength Length of the JSON being parsed
     */
    public static void logDeserializationStart(int jsonLength) {
        logger.debug("Starting deserialization of JSON (length: {} chars)", jsonLength);
    }

    /**
     * Logs bundle deserialization completion.
     *
     * @param bundle The deserialized bundle
     */
    public static void logDeserializationComplete(BundleObject bundle) {
        if (bundle == null) {
            logger.warn("Deserialization completed with null bundle");
            return;
        }

        logger.info("Successfully deserialized bundle {} with {} objects",
            bundle.getId(), bundle.getObjects().size());
    }

    /**
     * Logs bundle deserialization error.
     *
     * @param error The error that occurred
     */
    public static void logDeserializationError(Exception error) {
        logger.error("Failed to deserialize bundle: {}", error.getMessage(), error);
    }

    /**
     * Logs object addition to bundle.
     *
     * @param bundleId The bundle ID
     * @param object The object being added
     */
    public static void logObjectAddition(String bundleId, BundleableObject object) {
        logger.debug("Adding object {} (type: {}) to bundle {}",
            object.getId(), object.getType(), bundleId);
    }

    /**
     * Logs object removal from bundle.
     *
     * @param bundleId The bundle ID
     * @param objectId The ID of the object being removed
     */
    public static void logObjectRemoval(String bundleId, String objectId) {
        logger.debug("Removing object {} from bundle {}", objectId, bundleId);
    }

    /**
     * Logs bundle merge operation.
     *
     * @param sourceCount Number of source bundles
     * @param resultCount Number of objects in merged bundle
     */
    public static void logBundleMerge(int sourceCount, int resultCount) {
        logger.info("Merged {} bundles into single bundle with {} objects",
            sourceCount, resultCount);
    }

    /**
     * Logs bundle validation start.
     *
     * @param bundleId The bundle ID being validated
     */
    public static void logValidationStart(String bundleId) {
        logger.debug("Starting validation of bundle {}", bundleId);
    }

    /**
     * Logs bundle validation result.
     *
     * @param bundleId The bundle ID that was validated
     * @param isValid Whether the bundle is valid
     * @param errorCount Number of validation errors
     */
    public static void logValidationResult(String bundleId, boolean isValid, int errorCount) {
        if (isValid) {
            logger.info("Bundle {} validation successful", bundleId);
        } else {
            logger.warn("Bundle {} validation failed with {} errors", bundleId, errorCount);
        }
    }
}