package lab.auth.gui;

import java.util.*;
import java.util.regex.Pattern;
import static lab.auth.gui.HostGuiSelectors.*;

/** Public editor-text correlation; no message or credential content is returned as evidence. */
final class HostGuiMessages {
    private HostGuiMessages() {}
    static boolean request(String text) {
        int end=text.indexOf('\n');String first=(end<0?text:text.substring(0,end)).stripTrailing();
        return first.matches("[A-Z]+ .+ HTTP/[0-9.]+")&&text.contains("Host:");
    }
    static String nonce(String request,String previous,String next) {
        if(!previous.matches("h[0-9a-f]{16}")||!next.matches("h[0-9a-f]{16}")||previous.equals(next)||request.length()>65536||!request(request))throw new Failure("GUI_REQUEST_INPUT");
        int boundary=request.indexOf("\r\n\r\n");if(boundary<0)boundary=request.indexOf("\n\n");
        if(boundary<0)throw new Failure("GUI_REQUEST_INPUT");
        String headers=request.substring(0,boundary),body=request.substring(boundary);
        var nonce=Pattern.compile("(?im)^X-AuthLab-Request: "+Pattern.quote(previous)+"\\r?$").matcher(headers);
        if(nonce.results().count()!=1||headers.contains(next))throw new Failure("GUI_REQUEST_NONCE");
        String updated=headers.replaceFirst("(?im)^(X-AuthLab-Request: )"+Pattern.quote(previous)+"(?=\\r?$)","$1"+next);
        int firstEnd=updated.indexOf('\n');
        updated=updated.substring(0,firstEnd).replace("host_probe="+previous,"host_probe="+next)+updated.substring(firstEnd);
        return updated+body;
    }
    static Integer response(String text,String nonce) {
        if(!nonce.matches("h[0-9a-f]{16}"))throw new Failure("GUI_REQUEST_NONCE");
        int boundary=text.indexOf("\r\n\r\n");if(boundary<0)boundary=text.indexOf("\n\n");
        if(boundary<0||boundary>65536)return null;
        String headers=text.substring(0,boundary);
        var status=Pattern.compile("^HTTP/[0-9.]+ ([1-5][0-9]{2})(?:[ \\r\\n]|$)").matcher(headers);
        if(!status.find())return null;
        var correlation=Pattern.compile("(?im)^X-AuthLab-Request: ([^\\r\\n]*)\\r?$").matcher(headers);
        var values=correlation.results().map(match->match.group(1).trim()).toList();
        return values.equals(List.of(nonce))?Integer.valueOf(status.group(1)):null;
    }
}
