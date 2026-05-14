package security.whisper.javastix.taxii.exception;

/**
 * Raised on TAXII 5xx responses - the server acknowledged the request but
 * failed to fulfil it.
 */
public class TaxiiServerException extends TaxiiException {

    private static final long serialVersionUID = 1L;

    public TaxiiServerException(String message, int httpStatus) {
        super(message, httpStatus);
    }
}
