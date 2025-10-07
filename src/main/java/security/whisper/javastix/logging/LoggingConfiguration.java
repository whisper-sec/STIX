package security.whisper.javastix.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Centralized logging configuration for the STIX library.
 * Provides utilities for configuring log levels, MDC context, and performance logging.
 *
 * @since 1.3.0
 */
public class LoggingConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(LoggingConfiguration.class);

    /**
     * MDC keys for contextual logging.
     */
    public static final String MDC_BUNDLE_ID = "bundle.id";
    public static final String MDC_OBJECT_ID = "object.id";
    public static final String MDC_OBJECT_TYPE = "object.type";
    public static final String MDC_OPERATION = "operation";
    public static final String MDC_USER = "user";
    public static final String MDC_REQUEST_ID = "request.id";

    /**
     * Private constructor to prevent instantiation.
     */
    private LoggingConfiguration() {
    }

    /**
     * Sets up MDC context for bundle operations.
     *
     * @param bundleId The bundle ID
     */
    public static void setBundleContext(String bundleId) {
        if (bundleId != null) {
            MDC.put(MDC_BUNDLE_ID, bundleId);
        }
    }

    /**
     * Sets up MDC context for object operations.
     *
     * @param objectId The object ID
     * @param objectType The object type
     */
    public static void setObjectContext(String objectId, String objectType) {
        if (objectId != null) {
            MDC.put(MDC_OBJECT_ID, objectId);
        }
        if (objectType != null) {
            MDC.put(MDC_OBJECT_TYPE, objectType);
        }
    }

    /**
     * Sets the current operation in MDC.
     *
     * @param operation The operation name
     */
    public static void setOperation(String operation) {
        if (operation != null) {
            MDC.put(MDC_OPERATION, operation);
        }
    }

    /**
     * Sets the request ID in MDC.
     *
     * @param requestId The request ID
     */
    public static void setRequestId(String requestId) {
        if (requestId != null) {
            MDC.put(MDC_REQUEST_ID, requestId);
        }
    }

    /**
     * Clears the MDC context.
     */
    public static void clearContext() {
        MDC.clear();
    }

    /**
     * Clears specific MDC keys.
     *
     * @param keys The keys to clear
     */
    public static void clearContextKeys(String... keys) {
        for (String key : keys) {
            MDC.remove(key);
        }
    }

    /**
     * Executes an operation with timing and logging.
     *
     * @param operationName The operation name
     * @param operation The operation to execute
     * @param <T> The return type
     * @return The operation result
     */
    public static <T> T executeWithTiming(String operationName, SupplierWithException<T> operation) {
        long startTime = System.currentTimeMillis();
        setOperation(operationName);

        try {
            logger.debug("Starting operation: {}", operationName);
            T result = operation.get();
            long duration = System.currentTimeMillis() - startTime;
            logger.info("Completed operation '{}' in {}ms", operationName, duration);
            return result;
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            logger.error("Failed operation '{}' after {}ms: {}", operationName, duration, e.getMessage(), e);
            throw new RuntimeException("Operation failed: " + operationName, e);
        } finally {
            MDC.remove(MDC_OPERATION);
        }
    }

    /**
     * Executes an operation with timing and logging (void return).
     *
     * @param operationName The operation name
     * @param operation The operation to execute
     */
    public static void executeWithTiming(String operationName, RunnableWithException operation) {
        executeWithTiming(operationName, () -> {
            operation.run();
            return null;
        });
    }

    /**
     * Logs entry to a method.
     *
     * @param methodName The method name
     * @param params The method parameters
     */
    public static void logMethodEntry(String methodName, Object... params) {
        if (logger.isTraceEnabled()) {
            if (params.length > 0) {
                logger.trace("Entering method '{}' with parameters: {}", methodName, params);
            } else {
                logger.trace("Entering method '{}'", methodName);
            }
        }
    }

    /**
     * Logs exit from a method.
     *
     * @param methodName The method name
     * @param result The method result (optional)
     */
    public static void logMethodExit(String methodName, Object result) {
        if (logger.isTraceEnabled()) {
            if (result != null) {
                logger.trace("Exiting method '{}' with result: {}", methodName, result);
            } else {
                logger.trace("Exiting method '{}'", methodName);
            }
        }
    }

    /**
     * Logs a performance metric.
     *
     * @param metricName The metric name
     * @param value The metric value
     * @param unit The unit of measurement
     */
    public static void logMetric(String metricName, Number value, String unit) {
        logger.info("METRIC: {} = {} {}", metricName, value, unit);
    }

    /**
     * Checks if debug logging is enabled.
     *
     * @return true if debug logging is enabled
     */
    public static boolean isDebugEnabled() {
        return logger.isDebugEnabled();
    }

    /**
     * Checks if trace logging is enabled.
     *
     * @return true if trace logging is enabled
     */
    public static boolean isTraceEnabled() {
        return logger.isTraceEnabled();
    }

    /**
     * Functional interface for suppliers that can throw exceptions.
     */
    @FunctionalInterface
    public interface SupplierWithException<T> {
        T get() throws Exception;
    }

    /**
     * Functional interface for runnables that can throw exceptions.
     */
    @FunctionalInterface
    public interface RunnableWithException {
        void run() throws Exception;
    }

    /**
     * Creates a structured log message for errors.
     *
     * @param errorCode The error code
     * @param message The error message
     * @param details Additional details
     * @return Formatted error message
     */
    public static String formatError(String errorCode, String message, Object... details) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ERROR:").append(errorCode).append("] ").append(message);

        if (details.length > 0) {
            sb.append(" | Details: ");
            for (int i = 0; i < details.length; i += 2) {
                if (i + 1 < details.length) {
                    sb.append(details[i]).append("=").append(details[i + 1]);
                    if (i + 2 < details.length) {
                        sb.append(", ");
                    }
                }
            }
        }

        return sb.toString();
    }
}