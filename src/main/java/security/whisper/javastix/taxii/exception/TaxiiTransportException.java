package security.whisper.javastix.taxii.exception;

/**
 * Wraps low-level {@link java.io.IOException} or interruption raised by the
 * underlying HTTP transport. Network-layer faults surface as this type so
 * callers can distinguish them from server-reported errors.
 */
public class TaxiiTransportException extends TaxiiException {

    private static final long serialVersionUID = 1L;

    public TaxiiTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
