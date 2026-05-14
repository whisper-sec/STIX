package security.whisper.javastix.taxii.exception;

/**
 * Raised on TAXII responses indicating authentication or authorization
 * failure (HTTP 401 and 403).
 */
public class TaxiiAuthException extends TaxiiException {

    private static final long serialVersionUID = 1L;

    public TaxiiAuthException(String message, int httpStatus) {
        super(message, httpStatus);
    }
}
