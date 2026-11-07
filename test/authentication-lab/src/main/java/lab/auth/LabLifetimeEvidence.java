package lab.auth;

import com.google.gson.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Projects existing lifetime, coordinator and protected-recovery assertions without calculating expiry itself. */
final class LabLifetimeEvidence {
    private LabLifetimeEvidence() {}
    static boolean supports(String id){return id.startsWith("CORE.lifetime.");}
    static long n(JsonObject value,String key){return LabRun.number(value,key,true);}
    static boolean b(JsonObject value,String key){if(!value.get(key).getAsJsonPrimitive().isBoolean())throw new IllegalArgumentException();return value.get(key).getAsBoolean();}
    static boolean keys(JsonObject value,String... fields){return value.keySet().equals(Set.of(fields));}
    static boolean valid(String id,JsonObject actual) {
        try {
            return switch(id) {
                case "CORE.lifetime.fresh" -> keys(actual,"attempts","waitingRequests","workers","callers","cachedVersionMatches","cachedImmediate")&&n(actual,"attempts")==1&&n(actual,"waitingRequests")==0&&n(actual,"workers")==0&&n(actual,"callers")==100&&b(actual,"cachedVersionMatches")&&b(actual,"cachedImmediate");
                case "CORE.lifetime.opaque-age" -> {
                    if(!keys(actual,"windows")||actual.getAsJsonArray("windows").size()!=5)yield false;
                    boolean valid=true;
                    for(var item:actual.getAsJsonArray("windows")) {var window=item.getAsJsonObject();valid&=keys(window,"usableBefore","usableAtExpiry","usableNanos","refreshNanos")&&b(window,"usableBefore")&&!b(window,"usableAtExpiry")&&n(window,"usableNanos")==TimeUnit.SECONDS.toNanos(5)&&n(window,"refreshNanos")==TimeUnit.MILLISECONDS.toNanos(2500);}
                    yield valid;
                }
                case "CORE.lifetime.exact-expiry" -> keys(actual,"expiredCause","remainingNanos","refreshNanos","maxAgeCapNanos")&&LabRun.text(actual,"expiredCause").equals("TOKEN_EXPIRED")&&n(actual,"remainingNanos")==100_000_000&&n(actual,"refreshNanos")==50_000_000&&n(actual,"maxAgeCapNanos")==TimeUnit.DAYS.toNanos(1);
                case "CORE.lifetime.refresh-skew" -> keys(actual,"usableNanos","refreshNanos","wallExpired","monotonicExpired","forwardRefreshDelay","backwardRefreshDelay")&&n(actual,"usableNanos")==TimeUnit.SECONDS.toNanos(20)&&n(actual,"refreshNanos")==TimeUnit.SECONDS.toNanos(10)&&b(actual,"wallExpired")&&b(actual,"monotonicExpired")&&n(actual,"forwardRefreshDelay")==0&&n(actual,"backwardRefreshDelay")==TimeUnit.SECONDS.toNanos(9);
                case "CORE.lifetime.usable-during-refresh","CORE.lifetime.failed-refresh-usable-old" -> keys(actual,"duringRefreshSameVersion","afterFailureSameVersion","expiredSnapshotAbsent","attempts","queuedCycles","waitingRequests")&&b(actual,"duringRefreshSameVersion")&&b(actual,"afterFailureSameVersion")&&b(actual,"expiredSnapshotAbsent")&&n(actual,"attempts")==3&&n(actual,"queuedCycles")==1&&n(actual,"waitingRequests")==0;
                case "CORE.lifetime.late-old-401" -> keys(actual,"oldVersion","newVersion","lateInvalidated","latePreservedCurrent","currentInvalidated","repeatedInvalidated","bodyReads")&&n(actual,"newVersion")>n(actual,"oldVersion")&&n(actual,"lateInvalidated")==0&&b(actual,"latePreservedCurrent")&&n(actual,"currentInvalidated")==1&&n(actual,"repeatedInvalidated")==0&&n(actual,"bodyReads")==0;
                case "CORE.lifetime.server-revoked" -> keys(actual,"initialAccount","initialIssuance","originalStatus","replacementAccount","replacementIssuance","replacementStatus","recoveryAttempts","replays","waitingRequests")&&LabRun.text(actual,"initialAccount").equals("user2")&&LabRun.text(actual,"replacementAccount").equals("user2")&&LabRun.text(actual,"initialIssuance").matches("s[0-9]+")&&LabRun.text(actual,"replacementIssuance").matches("s[0-9]+")&&!LabRun.text(actual,"initialIssuance").equals(LabRun.text(actual,"replacementIssuance"))&&n(actual,"originalStatus")==401&&n(actual,"replacementStatus")==200&&n(actual,"recoveryAttempts")==1&&n(actual,"replays")==1&&n(actual,"waitingRequests")==0;
                default -> false;
            };
        }catch(RuntimeException malformed){return false;}
    }
    static List<ScenarioCatalog.Fact> facts(String id,JsonObject actual){return valid(id,actual)?List.of(new ScenarioCatalog.Fact("outcome","Correct usable snapshot and version-specific invalidation across controlled clocks.")):List.of();}
}
