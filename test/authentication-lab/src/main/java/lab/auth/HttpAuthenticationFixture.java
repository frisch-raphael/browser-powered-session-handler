package lab.auth;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.GlobalEventExecutor;
import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Local multi-account applications with actual connection-bound NTLM and independent proof verification. */
public final class HttpAuthenticationFixture implements AutoCloseable {
    public enum Protocol { BASIC, NTLM_V1, NTLM_V2 }
    public record Observation(String user, Protocol protocol, String connection, String method, String path, int bodyBytes) { }
    public record WireRequest(String method, String path, String connection, int bodyBytes) { }
    private final Protocol protocol;
    private final Map<String,String> users;
    private final NioEventLoopGroup acceptors = new NioEventLoopGroup(1), workers = new NioEventLoopGroup(2);
    private final DefaultChannelGroup channels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    private final Channel listener;
    private final SSLContext tls;
    public final AtomicInteger applicationAuthorizations=new AtomicInteger(), unexpectedBasicCredentials=new AtomicInteger();
    public final AtomicInteger handshakes = new AtomicInteger(), applicationPosts = new AtomicInteger(), leakedDirectives = new AtomicInteger();
    public final java.util.concurrent.atomic.AtomicReference<String> failureClass = new java.util.concurrent.atomic.AtomicReference<>();
    public final List<Observation> observations = new CopyOnWriteArrayList<>();
    public final java.util.concurrent.CompletableFuture<Void> releaseResponse=new java.util.concurrent.CompletableFuture<>();
    public final List<WireRequest> requests = new CopyOnWriteArrayList<>();

    public HttpAuthenticationFixture(Protocol protocol, Map<String,String> users, SSLContext tls) throws InterruptedException {
        this.protocol=protocol;this.users=Map.copyOf(users);this.tls=tls;
        listener = new ServerBootstrap().group(acceptors,workers).channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override protected void initChannel(SocketChannel channel) {
                        channels.add(channel);
                        if(tls!=null) {var engine=tls.createSSLEngine();engine.setUseClientMode(false);channel.pipeline().addLast(new SslHandler(engine));}
                        channel.pipeline().addLast(new HttpServerCodec(),new HttpObjectAggregator(9*1024*1024),new Application());
                    }
                }).bind("127.0.0.1",0).sync().channel();
    }

    public URI url(String path) {return URI.create((tls==null?"http":"https")+"://127.0.0.1:"+((InetSocketAddress)listener.localAddress()).getPort()+path);}

    private final class Application extends SimpleChannelInboundHandler<FullHttpRequest> {
        private NtlmChallengeVerifier verifier;
        private String authenticated;
        private boolean rechallenged;
        @Override protected void channelRead0(ChannelHandlerContext context,FullHttpRequest request) throws Exception {
            if(request.headers().contains("BPSP-HTTP-AUTHENT"))leakedDirectives.incrementAndGet();
            String path=URI.create(request.uri()).getPath();
            requests.add(new WireRequest(request.method().name(),path,context.channel().id().asLongText(),request.content().readableBytes()));
            if(path.equals("/large-header-challenge")) {largeHeaders(context,401);return;}
            if(path.startsWith("/large-challenge")) {
                var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.UNAUTHORIZED,
                        io.netty.buffer.Unpooled.wrappedBuffer(new byte[16*1024*1024+1]));
                response.headers().set("WWW-Authenticate",protocol==Protocol.BASIC?"Basic realm=\"lab\"":"NTLM");
                if(path.endsWith("chunked"))response.headers().set("Transfer-Encoding","chunked");
                else response.headers().set("Content-Length",response.content().readableBytes());
                context.writeAndFlush(response);return;
            }
            if(path.equals("/anonymous-page")) {reply(context,200,"<link rel='icon' href='data:,'><p>Anonymous</p>",null,false,"text/html");return;}
            // Deliberately broken fixture: application work occurs before authentication.
            if(path.equals("/action-before-auth") && request.method().name().equals("POST"))applicationPosts.incrementAndGet();
            if(path.equals("/anonymous")) {reply(context,200,"anonymous",null,false);return;}
            String authorization=request.headers().get("Authorization");
            if("Bearer application".equals(authorization))applicationAuthorizations.incrementAndGet();
            if(path.equals("/rechallenge") && protocol!=Protocol.BASIC && authenticated!=null && !rechallenged) {
                rechallenged=true;authenticated=null;verifier=null;
                reply(context,401,"authentication expired","NTLM",false);return;
            }
            if(protocol==Protocol.BASIC) {
                authenticated=null;
                if(authorization!=null && authorization.startsWith("Basic ")) {
                    String value=new String(Base64.getDecoder().decode(authorization.substring(6)),StandardCharsets.UTF_8);
                    int separator=value.indexOf(':');
                    if(separator>0 && !users.containsKey(value.substring(0,separator)))unexpectedBasicCredentials.incrementAndGet();
                    if(separator>0 && value.substring(separator+1).equals(users.get(value.substring(0,separator)))) {
                        authenticated=value.substring(0,separator); handshakes.incrementAndGet();
                    }
                }
            } else if(authorization!=null && authorization.startsWith("NTLM ")) {
                byte[] message=Base64.getDecoder().decode(authorization.substring(5));
                if(NtlmChallengeVerifier.type(message)==1) {
                    authenticated=null;
                    verifier=new NtlmChallengeVerifier(protocol==Protocol.NTLM_V2,binding(context));
                    reply(context,401,"challenge","NTLM "+Base64.getEncoder().encodeToString(verifier.challenge(message)),false);return;
                }
                if(verifier!=null) {
                    authenticated=verifier.verify(message,users);verifier=null;
                    if(authenticated!=null)handshakes.incrementAndGet();
                }
            }
            if(path.equals("/reject"))authenticated=null;
            if(authenticated==null) {reply(context,401,"authentication required",protocol==Protocol.BASIC?"Basic realm=\"lab\", charset=\"UTF-8\"":"NTLM",false);return;}
            observations.add(new Observation(authenticated,protocol,context.channel().id().asLongText(),request.method().name(),path,request.content().readableBytes()));
            if(path.equals("/large-header-final")) {largeHeaders(context,200);return;}
            if(request.method().name().equals("POST") && !path.equals("/action-before-auth"))applicationPosts.incrementAndGet();
            if(path.equals("/application-page")) {reply(context,200,"<link rel='icon' href='data:,'><p>Authenticated</p>",null,false,"text/html");return;}
            if(path.equals("/login")) {
                if(request.method().name().equals("GET")) {
                    reply(context,200,"<form method='post' action='/login'><label>User<input id='user' name='user'></label><button id='submit'>Sign in</button></form>",null,false,"text/html");return;
                }
                String form=request.content().toString(StandardCharsets.UTF_8);
                if(!form.equals("user="+authenticated)) {reply(context,403,"wrong application user",null,false);return;}
                byte[] body="<p id='signed-in'>Signed in</p>".getBytes(StandardCharsets.UTF_8);
                var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.OK,io.netty.buffer.Unpooled.wrappedBuffer(body));
                response.headers().set("Content-Length",body.length).set("Content-Type","text/html")
                        .set("Set-Cookie","app-session=session-"+authenticated+"; Path=/; HttpOnly; SameSite=Lax");
                context.writeAndFlush(response);return;
            }
            if(path.equals("/drop")) {context.close();return;}
            if(path.equals("/truncated")) {
                var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.OK,
                        io.netty.buffer.Unpooled.wrappedBuffer(new byte[]{1}));
                response.headers().set("Content-Length",100).set("Connection","close");
                context.writeAndFlush(response).addListener(io.netty.channel.ChannelFutureListener.CLOSE);return;
            }
            if(path.equals("/server-error")) {reply(context,500,"fixture error",null,false);return;}
            if(path.equals("/forbidden")) {reply(context,403,"forbidden",null,false);return;}
            if(path.equals("/large")) {reply(context,200,"x".repeat(16*1024*1024+1),null,false);return;}
            String body=new com.google.gson.Gson().toJson(Map.of("user",authenticated,"protocol",protocol.name()));
            if(path.equals("/held"))releaseResponse.whenComplete((value,error)->context.executor().execute(()->reply(context,200,body,null,false)));
            else if(path.equals("/slow"))context.executor().schedule(()->reply(context,200,body,null,false),1,TimeUnit.SECONDS);
            else reply(context,200,body,null,path.equals("/close"));
        }
        @Override public void exceptionCaught(ChannelHandlerContext context,Throwable failure) { failureClass.set(failure.getClass().getSimpleName()); context.close(); }
    }

    private static void reply(ChannelHandlerContext context,int status,String body,String challenge,boolean close) {
        reply(context,status,body,challenge,close,"application/json");
    }
    private void largeHeaders(ChannelHandlerContext context,int status) {
        var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.valueOf(status));
        response.headers().set("Content-Length",0);
        if(status==401)response.headers().set("WWW-Authenticate",protocol==Protocol.BASIC?"Basic realm=\"lab\"":"NTLM");
        for(int index=0;index<80;index++)response.headers().add("X-Lab-"+index,"x".repeat(1024));
        context.writeAndFlush(response);
    }
    private static void reply(ChannelHandlerContext context,int status,String body,String challenge,boolean close,String contentType) {
        byte[] bytes=body.getBytes(StandardCharsets.UTF_8);
        var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.valueOf(status),io.netty.buffer.Unpooled.wrappedBuffer(bytes));
        response.headers().set("Content-Length",bytes.length).set("Content-Type",contentType);
        if(challenge!=null)response.headers().set("WWW-Authenticate",challenge);
        if(close)response.headers().set("Connection","close");
        var sent=context.writeAndFlush(response);if(close)sent.addListener(io.netty.channel.ChannelFutureListener.CLOSE);
    }

    /** Independently encoded server-side CBT for the dedicated RSA lab certificates. */
    private static byte[] binding(ChannelHandlerContext context) throws Exception {
        SslHandler ssl=context.pipeline().get(SslHandler.class);if(ssl==null)return null;
        var certificate=(java.security.cert.X509Certificate)ssl.engine().getSession().getLocalCertificates()[0];
        String digestName=switch(certificate.getSigAlgOID()) {case "1.2.840.113549.1.1.12" -> "SHA-384"; case "1.2.840.113549.1.1.13" -> "SHA-512"; default -> "SHA-256";};
        byte[] digest=MessageDigest.getInstance(digestName).digest(certificate.getEncoded());
        byte[] prefix="tls-server-end-point:".getBytes(StandardCharsets.US_ASCII);
        ByteBuffer gss=ByteBuffer.allocate(20+prefix.length+digest.length).order(ByteOrder.LITTLE_ENDIAN);
        gss.position(16);gss.putInt(prefix.length+digest.length).put(prefix).put(digest);
        return MessageDigest.getInstance("MD5").digest(gss.array());
    }

    public boolean isClosed() { return !listener.isOpen() && channels.isEmpty() && acceptors.isTerminated() && workers.isTerminated(); }

    @Override public void close() {
        listener.close().syncUninterruptibly();channels.close().awaitUninterruptibly();
        acceptors.shutdownGracefully(0,2,TimeUnit.SECONDS).syncUninterruptibly();
        workers.shutdownGracefully(0,2,TimeUnit.SECONDS).syncUninterruptibly();
    }
}
