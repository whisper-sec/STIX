package security.whisper.javastix.taxii.exception;

/**
 * Raised when the TAXII server returns HTTP 404 for a requested resource
 * (discovery, API root, collection, or object endpoint).
 */
public class TaxiiNotFoundException extends TaxiiException {

    private static final long serialVersionUID = 1L;

    public TaxiiNotFoundException(String message) {
        super(message, 404);
    }
}
