package bpsh.journey;



/**
 * Reports native format failures using safe field paths and reasons, without raw secret values.
 */
public final class ConfigurationException extends IllegalArgumentException {
    /**
     * Creates a validation failure from an already redacted message.
     *
     * @param message Safe field-path/reason text; never a raw parser exception or secret value.
     */
    public ConfigurationException(String message) { super(message); }
}
