package bpsh.burp.http;

import bpsh.authentication.AuthenticationFailure;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;

/** Consumes the HTTP identity directive and every old Authorization header before resolving capture tags. */
final class HttpAuthenticationDirective {
    static final String HEADER="BPSP-HTTP-AUTHENT";
    record Selection(String alias,byte[] request,byte[] applicationHeaders,int bodyOffset) {
        Selection {request=request.clone();applicationHeaders=applicationHeaders.clone();}
        @Override public byte[] request() {return request.clone();}
        @Override public byte[] applicationHeaders() {return applicationHeaders.clone();}
        /** Restores application Authorization for certificate-only requests without retaining a second body. */
        byte[] applicationAuthorizationRequest() {
            byte[] result=new byte[applicationHeaders.length+request.length-bodyOffset];
            System.arraycopy(applicationHeaders,0,result,0,applicationHeaders.length);
            System.arraycopy(request,bodyOffset,result,applicationHeaders.length,request.length-bodyOffset);return result;
        }
        @Override public String toString() {return "HttpAuthenticationDirective[redacted]";}
    }
    private HttpAuthenticationDirective() { }
    static boolean present(burp.api.montoya.core.ByteArray raw) {
        int end=raw.indexOf("\r\n\r\n");if(end<0)end=raw.length();
        for(int start=0;start<end;start+=8192)if(present(raw.subArray(start,Math.min(end,start+8192+128)).getBytes()))return true;
        return false;
    }
    static boolean present(byte[] raw) {
        int end=raw.length;
        for(int i=0;i+3<raw.length;i++)if(raw[i]==13 && raw[i+1]==10 && raw[i+2]==13 && raw[i+3]==10) {end=i;break;}
        return java.util.regex.Pattern.compile("(?im)^[ \\t]*BPSP-HTTP-AUTHENT[ \\t]*:").matcher(new String(raw,0,end,StandardCharsets.ISO_8859_1)).find();
    }

    static Selection consume(byte[] raw) throws AuthenticationFailure {return parse(raw,true);}
    /** Validates the same transport framing without introducing an explicit directive. */
    static Selection prepare(byte[] raw) throws AuthenticationFailure {return parse(raw,false);}
    private static Selection parse(byte[] raw,boolean requireDirective) throws AuthenticationFailure {
        int end=-1;
        for(int i=0;i+3<raw.length;i++)if(raw[i]==13 && raw[i+1]==10 && raw[i+2]==13 && raw[i+3]==10) {end=i;break;}
        if(end<0) {if(!requireDirective || present(raw))throw invalid("The tagged request needs valid HTTP/1.1 headers.");return null;}
        String head=new String(raw,0,end,StandardCharsets.ISO_8859_1);
        String[] lines=head.split("\r\n",-1);
        String directive=null;
        ArrayList<String> retained=new ArrayList<>();retained.add(lines[0]);
        ArrayList<String> application=new ArrayList<>();application.add(lines[0]);
        for(int i=1;i<lines.length;i++) {
            int colon=lines[i].indexOf(':');
            if(colon<0)continue;
            String name=lines[i].substring(0,colon).trim();
            if(name.equalsIgnoreCase(HEADER)) {
                if(directive!=null)throw invalid("Use exactly one BPSP-HTTP-AUTHENT header.");
                directive=lines[i].substring(colon+1).trim();
            }
        }
        if(directive==null && requireDirective)return null;
        if(end>65536 || lines[0].length()>16384)throw invalid("The tagged request exceeds the HTTP header or request-line limit.");
        String method=lines[0].split(" ",2)[0];
        if(method.equalsIgnoreCase("CONNECT"))throw invalid("Tagged HTTP authentication does not support CONNECT requests.");
        if(lines[0].regionMatches(true,0,"TRACE ",0,6))throw invalid("Tagged HTTP authentication does not support TRACE requests.");
        if(raw.length>NativeTagParser.MAX_OUTPUT_BYTES)throw invalid("The tagged request exceeds the 4 MiB message ceiling.");
        if(!lines[0].matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^ \\r\\n]+ HTTP/1\\.1"))throw invalid("Tagged HTTP authentication requires an HTTP/1.1 request.");
        String alias=null;
        if(directive!=null) {
            if(!requireDirective)throw invalid("An automatic request cannot introduce an HTTP authentication directive.");
            var tree=NativeTagParser.parse(directive,directive.length(),new NativeTagParser.Budget());
            if(tree.nodes.size()!=1 || !(tree.nodes.getFirst() instanceof NativeTagParser.Reference reference) || reference.tokenName()!=null)
                throw invalid("Use one journey reference, for example BPSP-HTTP-AUTHENT: <@user-a/>.");
            alias=reference.alias();
        }
        int contentLengths=0, hosts=0;long contentLength=-1;
        for(int i=1;i<lines.length;i++) {
            String line=lines[i];int colon=line.indexOf(':');
            if(colon<=0 || line.charAt(0)==' ' || line.charAt(0)=='\t' || !line.substring(0,colon).matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))
                throw invalid("Tagged HTTP authentication does not support folded or malformed headers.");
            String name=line.substring(0,colon).toLowerCase(Locale.ROOT);
            if(name.equals("host") && ++hosts>1)throw invalid("The tagged request needs one Host header.");
            if(name.equals("content-length")) {
                String value=line.substring(colon+1).trim();
                if(++contentLengths>1 || !value.matches("[0-9]{1,10}"))throw invalid("The tagged request has ambiguous body framing.");
                contentLength=Long.parseLong(value);
            }
            if(name.equals("transfer-encoding") || name.equals("upgrade"))throw invalid("Tagged HTTP authentication does not support transfer-encoded requests or protocol upgrades.");
            if(!name.equals(HEADER.toLowerCase(Locale.ROOT))) {application.add(line);if(!name.equals("authorization"))retained.add(line);}
        }
        int bodyBytes=raw.length-end-4;
        if(hosts!=1 || contentLength>=0 && contentLength!=bodyBytes || contentLength<0 && bodyBytes>0)
            throw invalid("Correct the tagged request's Host and Content-Length headers before authenticating.");
        byte[] prefix=(String.join("\r\n",retained)+"\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream stripped=new ByteArrayOutputStream();stripped.writeBytes(prefix);stripped.writeBytes(Arrays.copyOfRange(raw,end+4,raw.length));
        byte[] applicationPrefix=(String.join("\r\n",application)+"\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        return new Selection(alias,stripped.toByteArray(),applicationPrefix,prefix.length);
    }
    private static AuthenticationFailure invalid(String message) {return NativeTagParser.syntax(message);}
}
