import java.security.PrivilegedExceptionAction;

public class KerberosTlsEchoServer {
    private SimpleEchoServer mServer;

    public KerberosTlsEchoServer(int port) {
        mServer = new SimpleEchoServer(port, false);
    }

    public void start() throws Exception {
        Jaas.loginAndAction("server", new KerberosServerStartAction(mServer));
    }

    public void serve() throws Exception {
        Jaas.loginAndAction("server", new KerberosServerServeAction(mServer));
    }

    public void stop() throws Exception {
        Jaas.loginAndAction("server", new KerberosServerStopAction(mServer));
    }

    private static class KerberosServerStartAction implements PrivilegedExceptionAction {
        private SimpleEchoServer mServer;
        public KerberosServerStartAction(SimpleEchoServer server) {
            mServer = server;
        }
        public Object run() throws Exception {
            mServer.start();
            return null;
        }
    }

    private static class KerberosServerServeAction implements PrivilegedExceptionAction {
        private SimpleEchoServer mServer;
        public KerberosServerServeAction(SimpleEchoServer server) {
            mServer = server;
        }
        public Object run() throws Exception {
            mServer.serve();
            return null;
        }
    }

    private static class KerberosServerStopAction implements PrivilegedExceptionAction {
        private SimpleEchoServer mServer;
        public KerberosServerStopAction(SimpleEchoServer server) {
            mServer = server;
        }
        public Object run() throws Exception {
            mServer.stop();
            return null;
        }
    }
}
