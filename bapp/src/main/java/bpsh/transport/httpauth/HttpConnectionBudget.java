package bpsh.transport.httpauth;

import org.apache.hc.client5.http.io.ManagedHttpClientConnection;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.io.HttpConnectionFactory;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.Timeout;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;

/** Pinned HttpClient factory boundary; a permit covers creation, connect, TLS and idle retention. */
final class HttpConnectionBudget implements HttpConnectionFactory<ManagedHttpClientConnection> {
    private final ManagedHttpClientConnectionFactory factory=ManagedHttpClientConnectionFactory.builder()
            .http1Config(org.apache.hc.core5.http.config.Http1Config.custom().setMaxHeaderCount(256).setMaxLineLength(16384).build()).build();
    private int used,peak;
    synchronized int used() {return used;}
    synchronized int peak() {return peak;}
    private synchronized void reserve() throws IOException {
        if(used>=16)throw new IOException("HTTP authentication connection capacity is exhausted.");
        used++;peak=Math.max(used,peak);
    }
    private synchronized void release() {used--;}
    @Override public ManagedHttpClientConnection createConnection(Socket socket) throws IOException {
        reserve();
        try {return new Owned(factory.createConnection(socket));}
        catch(IOException|RuntimeException|Error failure) {release();throw failure;}
    }
    private final class Owned implements ManagedHttpClientConnection {
        private final ManagedHttpClientConnection delegate;
        private final AtomicBoolean released=new AtomicBoolean();
        Owned(ManagedHttpClientConnection delegate) {this.delegate=delegate;}
        private void check() throws IOException {if(released.get())throw new IOException("HTTP connection was retired.");}
        private void done() {if(released.compareAndSet(false,true))release();}
        @Override public void bind(Socket socket) throws IOException {
            check();try {delegate.bind(socket);}catch(IOException|RuntimeException failure) {close(CloseMode.IMMEDIATE);throw failure;}
        }
        @Override public void bind(SSLSocket tls,Socket socket) throws IOException {
            check();try {delegate.bind(tls,socket);}catch(IOException|RuntimeException failure) {close(CloseMode.IMMEDIATE);throw failure;}
        }
        @Override public Socket getSocket() {return delegate.getSocket();}
        @Override public SSLSession getSSLSession() {return delegate.getSSLSession();}
        @Override public void activate() {delegate.activate();}
        @Override public void passivate() {delegate.passivate();}
        @Override public boolean isConsistent() {return delegate.isConsistent();}
        @Override public boolean isOpen() {return !released.get() && delegate.isOpen();}
        @Override public boolean isStale() throws IOException {return delegate.isStale();}
        @Override public boolean isDataAvailable(Timeout timeout) throws IOException {return delegate.isDataAvailable(timeout);}
        @Override public void flush() throws IOException {delegate.flush();}
        @Override public void sendRequestHeader(ClassicHttpRequest request) throws HttpException,IOException {delegate.sendRequestHeader(request);}
        @Override public void sendRequestEntity(ClassicHttpRequest request) throws HttpException,IOException {delegate.sendRequestEntity(request);}
        @Override public void terminateRequest(ClassicHttpRequest request) throws HttpException,IOException {delegate.terminateRequest(request);}
        @Override public ClassicHttpResponse receiveResponseHeader() throws HttpException,IOException {
            var response=delegate.receiveResponseHeader();long bytes=2;
            for(var header:response.getHeaders()) {
                bytes+=header instanceof FormattedHeader formatted?formatted.getBuffer().length()+2L:header.getName().length()+header.getValue().length()+4L;
                if(bytes>65536)throw new IOException("The HTTP response headers exceed the transport limit.");
            }
            return response;
        }
        @Override public void receiveResponseEntity(ClassicHttpResponse response) throws HttpException,IOException {delegate.receiveResponseEntity(response);}
        @Override public EndpointDetails getEndpointDetails() {return delegate.getEndpointDetails();}
        @Override public SocketAddress getLocalAddress() {return delegate.getLocalAddress();}
        @Override public SocketAddress getRemoteAddress() {return delegate.getRemoteAddress();}
        @Override public ProtocolVersion getProtocolVersion() {return delegate.getProtocolVersion();}
        @Override public Timeout getSocketTimeout() {return delegate.getSocketTimeout();}
        @Override public void setSocketTimeout(Timeout timeout) {delegate.setSocketTimeout(timeout);}
        @Override public void close(CloseMode mode) {try {delegate.close(mode);}finally {done();}}
        @Override public void close() throws IOException {try {delegate.close();}finally {done();}}
    }
}
