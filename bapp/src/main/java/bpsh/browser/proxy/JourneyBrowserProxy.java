package bpsh.browser.proxy;

import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.journey.JourneyOrigins;
import com.microsoft.playwright.options.Proxy;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.concurrent.GlobalEventExecutor;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;

/** Attempt-local browser ingress. Netty handles sockets; the shared transport handles all destination requests. */
public final class JourneyBrowserProxy implements AutoCloseable {
    private final Function<URI,HttpAuthenticationService> destinations;
    private final bpsh.authentication.http.HttpMessageBody.Allocator bodies;
    private final Consumer<Throwable> failure;
    private final long deadline;
    private final ProxyCertificateFactory certificates;
    private final String username=random(), password=random();
    private final byte[] authorization=("Basic "+Base64.getEncoder().encodeToString((username+":"+password).getBytes(StandardCharsets.UTF_8))).getBytes(StandardCharsets.US_ASCII);
    private final NioEventLoopGroup acceptors=new NioEventLoopGroup(1), workers=new NioEventLoopGroup(2);
    private final DefaultChannelGroup clients=new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    private final AtomicInteger admitted=new AtomicInteger();
    private final AtomicBoolean closed=new AtomicBoolean();
    private final Channel listener;

    /** Destination selection must return immediately; exchange completion is always asynchronous. */
    public JourneyBrowserProxy(Function<URI,HttpAuthenticationService> destinations,bpsh.authentication.http.HttpMessageBody.Allocator bodies,Clock clock,long deadline,Consumer<Throwable> failure) throws Exception {
        this.destinations=destinations;this.bodies=bodies;this.deadline=deadline;this.failure=failure;
        ProxyCertificateFactory owned=null;
        try {
            owned=new ProxyCertificateFactory(clock);certificates=owned;
            listener=new ServerBootstrap().group(acceptors,workers).channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override protected void initChannel(SocketChannel channel) {
                            if(admitted.incrementAndGet()>64) {admitted.decrementAndGet();channel.close();return;}
                            clients.add(channel);channel.closeFuture().addListener(ignored->admitted.decrementAndGet());
                            channel.pipeline().addLast("idle",new IdleStateHandler(0,0,30));
                            channel.pipeline().addLast("http",new HttpServerCodec(16384,65536,8192));
                            channel.pipeline().addLast("application",new BrowserConnection());
                        }
                    }).bind("127.0.0.1",0).sync().channel();
        } catch(Exception error) {
            if(owned!=null)owned.close();acceptors.shutdownGracefully(0,1,TimeUnit.SECONDS);workers.shutdownGracefully(0,1,TimeUnit.SECONDS);
            throw error;
        }
    }

    public Proxy browserProxy() {return new Proxy("http://127.0.0.1:"+address().getPort()).setUsername(username).setPassword(password).setBypass("<-loopback>");}
    public InetSocketAddress address() {return (InetSocketAddress)listener.localAddress();}
    public String spkiSha256() {return certificates.spkiSha256();}

    private record Incoming(URI target,String method,ArrayList<HttpAuthenticationService.Header> headers,boolean keepAlive,boolean head) { }
    private record Pending(HttpAuthenticationService.Request request,HttpAuthenticationService.Delivery delivery,boolean keepAlive,boolean head) { }

    private final class BrowserConnection extends SimpleChannelInboundHandler<HttpObject> {
        private URI tunnel,connect;
        private Incoming incoming;
        private bpsh.authentication.http.HttpMessageBody.Builder receiving;
        private HttpAuthenticationService.Delivery admission;
        private int received;
        private boolean rejecting;
        private final ArrayDeque<Pending> queue=new ArrayDeque<>();
        private CompletableFuture<HttpAuthenticationService.Response> active;
        @Override protected void channelRead0(ChannelHandlerContext context,HttpObject message) throws Exception {
            if(rejecting)return;
            if(!message.decoderResult().isSuccess()) {stop(context,400,"Invalid HTTP request.");return;}
            if(message instanceof HttpRequest request)begin(context,request);
            if(!rejecting && message instanceof HttpContent content)content(context,content);
        }
        private void begin(ChannelHandlerContext context,HttpRequest request) throws Exception {
            if(incoming!=null || connect!=null)throw new IOException("Overlapping proxy request headers.");
            if(tunnel==null && !authorized(request)) {
                rejecting=true;
                var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED);
                response.headers().set("Proxy-Authenticate","Basic realm=\"BPSH owned authentication\"").set("Content-Length",0).set("Connection","close");
                context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);return;
            }
            if(request.method().equals(HttpMethod.CONNECT)) {
                if(tunnel!=null || active!=null || !queue.isEmpty() || HttpUtil.getContentLength(request,0)!=0 || HttpUtil.isTransferEncodingChunked(request)) {
                    stop(context,400,"Invalid CONNECT request.");return;
                }
                URI origin=URI.create("https://"+request.uri());
                if(origin.getRawQuery()!=null || origin.getRawFragment()!=null || origin.getRawPath()!=null && !origin.getRawPath().isEmpty())
                    throw new IOException("Invalid tunnel authority.");
                connect=JourneyOrigins.authenticationOrigin(origin);return;
            }
            if(request.headers().contains("Upgrade") || !request.protocolVersion().equals(HttpVersion.HTTP_1_1)) {
                stop(context,501,"This login proxy supports HTTP/1.1 without protocol upgrades.");return;
            }
            if(queue.size()>=4) {stop(context,503,"The login proxy is at capacity.");return;}
            URI target=URI.create(request.uri());
            if(tunnel!=null && !target.isAbsolute()) {
                if(!request.uri().startsWith("/") || request.uri().startsWith("//"))throw new IOException("Invalid tunneled request target.");
                target=URI.create(tunnel.toString()+request.uri());
            }
            URI origin=JourneyOrigins.authenticationOrigin(target);
            if(tunnel!=null && !origin.equals(tunnel))throw new IOException("A request cannot change its tunnel destination.");
            if(tunnel==null && !origin.getScheme().equals("http"))throw new IOException("HTTPS requires CONNECT.");
            String host=request.headers().get(HttpHeaderNames.HOST);
            if(host==null || request.headers().getAll(HttpHeaderNames.HOST).size()!=1 ||
                    !JourneyOrigins.authenticationOrigin(URI.create(origin.getScheme()+"://"+host)).equals(origin))
                throw new IOException("The Host header does not match the proxy destination.");
            if(HttpUtil.getContentLength(request,0)>HttpAuthenticationService.Request.MAX_BODY_BYTES) {stop(context,413,"The browser request exceeds the 8 MiB limit.");return;}
            var headers=new ArrayList<HttpAuthenticationService.Header>();
            request.headers().forEach(header->headers.add(new HttpAuthenticationService.Header(header.getKey(),header.getValue())));
            // No body chunks have been retained when this nonblocking admission runs.
            admission=destinations.apply(target).admit(deadline);
            incoming=new Incoming(target,request.method().name(),headers,HttpUtil.isKeepAlive(request),request.method().equals(HttpMethod.HEAD));
            receiving=bodies.builder(HttpAuthenticationService.Request.MAX_BODY_BYTES);received=0;
            if(HttpUtil.is100ContinueExpected(request))context.writeAndFlush(new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.CONTINUE));
        }
        private void content(ChannelHandlerContext context,HttpContent content) throws Exception {
            if(connect!=null) {
                if(content.content().isReadable()) {stop(context,400,"CONNECT must not contain a body.");return;}
                if(content instanceof LastHttpContent)upgrade(context);
                return;
            }
            if(incoming==null || receiving==null)throw new IOException("HTTP content arrived without request headers.");
            int count=content.content().readableBytes();
            if(count>HttpAuthenticationService.Request.MAX_BODY_BYTES-received) {stop(context,413,"The browser request exceeds the 8 MiB limit.");return;}
            received+=count;
            try {for(var view:content.content().nioBuffers())receiving.append(view);}
            catch(IOException capacity) {stop(context,503,"The browser HTTP buffer capacity is exhausted.");return;}
            if(content instanceof LastHttpContent last) {
                if(!last.trailingHeaders().isEmpty()) {stop(context,501,"Browser request trailers are unsupported.");return;}
                var body=receiving.finish();receiving=null;
                var metadata=incoming;incoming=null;
                var reserved=admission;admission=null;
                var request=new HttpAuthenticationService.Request(metadata.target(),metadata.method(),metadata.headers(),body,HttpAuthenticationService.AuthorizationPolicy.PRESERVE_APPLICATION);
                queue.add(new Pending(request,reserved,metadata.keepAlive(),metadata.head()));
                context.channel().config().setAutoRead(queue.size()<4);forward(context);
            }
        }
        private void upgrade(ChannelHandlerContext context) {
            tunnel=connect;connect=null;
            var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.OK);response.headers().set("Content-Length",0);
            context.writeAndFlush(response).addListener(sent->{
                if(!sent.isSuccess()) {context.close();return;}
                try {
                    var engine=certificates.engine(tunnel.getHost());var parameters=engine.getSSLParameters();
                    parameters.setApplicationProtocols(new String[]{"http/1.1"});engine.setSSLParameters(parameters);
                    context.pipeline().remove("http");context.pipeline().addAfter("idle","tls",new SslHandler(engine));
                    context.pipeline().addAfter("tls","http",new HttpServerCodec(16384,65536,8192));
                } catch(Exception error) {failed(context,error);}
            });
        }
        private boolean authorized(HttpRequest request) {
            String supplied=request.headers().get("Proxy-Authorization");
            return supplied!=null && request.headers().getAll("Proxy-Authorization").size()==1 &&
                    MessageDigest.isEqual(authorization,supplied.getBytes(StandardCharsets.US_ASCII));
        }
        private void forward(ChannelHandlerContext context) {
            if(active!=null || queue.isEmpty() || !context.channel().isActive())return;
            Pending next=queue.remove();context.channel().config().setAutoRead(queue.size()<4);
            try {
                active=next.delivery().exchange(next.request());
                active.whenComplete((response,error)->{
                    next.request().body().close();next.delivery().close();
                    try {context.executor().execute(()->{
                        active=null;
                        if(!context.channel().isActive()) {if(response!=null)response.close();return;}
                        if(error!=null) {failed(context,error);return;}
                        try {
                            boolean noBody=next.head() || response.status()==204 || response.status()==304;
                            var body=noBody?Unpooled.EMPTY_BUFFER:Unpooled.wrappedBuffer(response.body().buffers().toArray(java.nio.ByteBuffer[]::new));
                            var outgoing=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.valueOf(response.status()),body);
                            for(var header:response.headers())outgoing.headers().add(header.name(),header.value());
                            if(response.status()==204)outgoing.headers().remove("Content-Length");
                            else if(!noBody)outgoing.headers().set("Content-Length",response.body().length());
                            HttpUtil.setKeepAlive(outgoing,next.keepAlive());
                            var sent=context.writeAndFlush(outgoing);sent.addListener(done->response.close());
                            if(!next.keepAlive())sent.addListener(ChannelFutureListener.CLOSE);else forward(context);
                        } catch(RuntimeException failure) {response.close();failed(context,failure);}
                    });} catch(java.util.concurrent.RejectedExecutionException stopped) {if(response!=null)response.close();}
                });
            } catch(Exception error) {next.delivery().close();next.request().body().close();failed(context,error);}
        }
        private void stop(ChannelHandlerContext context,int status,String message) {
            rejecting=true;
            if(receiving!=null) {receiving.close();receiving=null;}
            if(admission!=null) {admission.close();admission=null;}
            incoming=null;reject(context,status,message);
        }
        private void failed(ChannelHandlerContext context,Throwable error) {
            try {failure.accept(error);}catch(RuntimeException ignored) { /* observations cannot prevent cleanup */ }
            stop(context,502,"The login proxy could not complete this request.");
        }
        @Override public void exceptionCaught(ChannelHandlerContext context,Throwable error) {
            if(error instanceof java.net.SocketException || error instanceof javax.net.ssl.SSLException || error instanceof io.netty.handler.codec.DecoderException)context.close();
            else failed(context,error);
        }
        @Override public void userEventTriggered(ChannelHandlerContext context,Object event) throws Exception {
            if(event instanceof IdleStateEvent)context.close();else super.userEventTriggered(context,event);
        }
        @Override public void channelInactive(ChannelHandlerContext context) {
            if(receiving!=null) {receiving.close();receiving=null;}
            if(admission!=null) {admission.close();admission=null;}
            for(Pending pending:queue) {pending.delivery().close();pending.request().body().close();}
            queue.clear();if(active!=null)active.cancel(true);
        }
    }

    private static void reject(ChannelHandlerContext context,int status,String message) {
        byte[] body=message.getBytes(StandardCharsets.UTF_8);
        var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.valueOf(status),Unpooled.wrappedBuffer(body));
        response.headers().set("Content-Length",body.length).set("Content-Type","text/plain; charset=utf-8").set("Connection","close");
        context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }
    private static String random() {byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    @Override public void close() {
        if(!closed.compareAndSet(false,true))return;
        listener.close().syncUninterruptibly();clients.close().awaitUninterruptibly();
        acceptors.shutdownGracefully(0,2,TimeUnit.SECONDS).syncUninterruptibly();
        workers.shutdownGracefully(0,2,TimeUnit.SECONDS).syncUninterruptibly();certificates.close();
    }
}
