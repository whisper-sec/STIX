package security.whisper.javastix.taxii.exception;

/**
 * Raised when a TAXII response violates the protocol contract - for example
 * an unexpected {@code Content-Type}, a malformed envelope, or missing
 * pagination headers when the server indicated more pages exist.
 */
public class TaxiiProtocolException extends TaxiiException {

    private static final long serialVersionUID = 1L;

    public TaxiiProtocolException(String message) {
        super(message);
    }

    public TaxiiProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
