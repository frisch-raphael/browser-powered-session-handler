package bpsh.authentication;



/** Fixed local preparation states; none contains browser or credential output. */
public enum AuthenticationStage {
    WAITING_FOR_CACHE("Waiting for browser setup..."),
    VERIFYING_CACHE("Verifying bundled browser files..."),
    EXTRACTING_BROWSER("Extracting bundled browser files..."),
    STARTING_DRIVER("Starting the browser driver..."),
    STARTING_BROWSER("Starting Chromium..."),
    AUTHENTICATING("Signing in...");
    private final String description;
    /** @param description Fixed safe display/event text. */
    AuthenticationStage(String description) { this.description = description; }
    /** @return Fixed safe display/event text. */
    public String description() { return description; }
}
