import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

public final class LocalTokenCache
{
    private final ReentrantLock lock = new ReentrantLock();
    private final ApiClient apiClient;
    private final AtomicReference<Config> configRef;

    private String token;
    private long validUntil;

    public LocalTokenCache(ApiClient apiClient, AtomicReference<Config> configRef)
    {
        this.apiClient = apiClient;
        this.configRef = configRef;
    }

    public void invalidate()
    {
        lock.lock();
        try {
            token = null;
            validUntil = 0;
        } finally {
            lock.unlock();
        }
    }

    public String get(boolean force) throws Exception
    {
        long now = System.currentTimeMillis() / 1000;
        Config cfg = configRef.get();
        long ttlSeconds = Math.max(5, cfg.refreshFrequencySeconds);

        if (!force && token != null && now < validUntil) {
            return token;
        }

        lock.lock();
        try {
            now = System.currentTimeMillis() / 1000;
            if (!force && token != null && now < validUntil) {
                return token;
            }

            token = apiClient.fetchToken(force);
            validUntil = now + ttlSeconds;
            return token;

        } finally {
            lock.unlock();
        }
    }
}
