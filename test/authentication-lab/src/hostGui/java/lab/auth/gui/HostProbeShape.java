package lab.auth.gui;

import java.nio.charset.StandardCharsets;
import java.util.*;

/** Safe passive facts shared by callback capture and its tests; no credential values escape. */
public final class HostProbeShape {
    private HostProbeShape() {}
    public static final int LIMIT=65_536;
    public record Header(String name,String value) {}
    public record Shape(String nonce,boolean invalidNonce,int authorizationHeaders,int cookieHeaders,
                        boolean c1,boolean c2,boolean nativeTag,boolean httpDirective,boolean sentinel,boolean truncated) {}
    public static Shape inspect(List<Header> headers,String path,byte[] body,boolean bodyTruncated) {
        int authorization=0,cookies=0,nonceCount=0,total=0;String nonce=null;
        boolean c1=false,c2=false,tag=false,directive=false,sentinel=false,truncated=bodyTruncated;
        for(Header header:headers) {
            if(header.name().length()>LIMIT||header.value().length()>LIMIT||total>LIMIT-header.name().length()-header.value().length()) {truncated=true;break;}
            total+=header.name().length()+header.value().length();tag|=header.value().contains("<@");
            switch(header.name().toLowerCase(Locale.ROOT)) {
                case "authorization" -> authorization++;
                case "cookie" -> {cookies++;for(String item:header.value().split(";")) {
                    String name=item.split("=",2)[0].trim();c1|=name.equals("LAB_C1");c2|=name.equals("LAB_C2");}}
                case "bpsp-http-authent" -> directive=true;
                case "x-authlab-sentinel" -> sentinel|=header.value().equals("unchanged");
                case "x-authlab-request" -> {nonceCount++;nonce=header.value();}
                default -> {}
            }
        }
        if(path.length()>LIMIT)truncated=true;else tag|=path.contains("<@");
        if(body.length>LIMIT)truncated=true;else tag|=new String(body,StandardCharsets.ISO_8859_1).contains("<@");
        boolean valid=nonceCount==1&&nonce.matches("h[0-9a-f]{16}");
        return new Shape(valid?nonce:null,nonceCount>0&&!valid,authorization,cookies,c1,c2,tag,directive,sentinel,truncated);
    }
}
