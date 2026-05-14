package security.whisper.javastix.taxii.exception;

/**
 * Base exception for all TAXII 2.1 client failures. Subclasses distinguish
 * transport, protocol, authentication, and server-side error categories so
 * callers can branch on type rather than parse messages.
 */
public class TaxiiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int httpStatus;

    public TaxiiException(String message) {
        this(message, -1, null);
    }

    public TaxiiException(String message, int httpStatus) {
        this(message, httpStatus, null);
    }

    public TaxiiException(String message, Throwable cause) {
        this(message, -1, cause);
    }

    public TaxiiException(String message, int httpStatus, Throwable cause) {
        super(message, cause);
        this.httpStatus = httpStatus;
    }

    /**
     * HTTP status code associated with this failure, or {@code -1} if the
     * failure was not produced by an HTTP response (e.g. transport I/O).
     */
    public int getHttpStatus() {
        return httpStatus;
    }
}
