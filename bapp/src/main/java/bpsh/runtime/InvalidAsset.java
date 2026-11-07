package bpsh.runtime;

import java.io.IOException;

/** Distinguishes a proved asset invariant failure from unrelated filesystem I/O. */
final class InvalidAsset extends IOException {
    private static final long serialVersionUID = 1L;
    /** @param message Internal invariant description, never forwarded as raw output. */
    InvalidAsset(String message) { super(message); }
}
