import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivilegedExceptionAction;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

public class SaslGssapiTlsEchoClient {
    private static final String MECH = "GSSAPI";
    private static final int PORT = 4568;
    private static final byte[] EMPTY = new byte[0];

    public static void main(String[] args) throws Exception {
        String service = args[0];
        String serverName = args[1];
        boolean mutualAuthRequired = Boolean.parseBoolean(args[2]);
        PrivilegedExceptionAction action =
            new SaslGssapiTlsEchoClientAction(service, serverName, PORT, mutualAuthRequired);
        Jaas.loginAndAction("client", action);
    }

    private static class SaslGssapiTlsEchoClientAction implements PrivilegedExceptionAction {
        private String mService;
        private String mServerName;
        private int mPort;
        private boolean mMutualAuthRequired;
        private CallbackHandler mCallbackHandler = null;

        public SaslGssapiTlsEchoClientAction(String service, String serverName, int port, boolean mutualAuthRequired) {
            mService = service;
            mServerName = serverName;
            mPort = port;
            mMutualAuthRequired = mutualAuthRequired;
        }

        public Object run() throws Exception {
            KeyManagerFactory kmf = null;
            if (mMutualAuthRequired) {
                String keyStoreFilePath = System.getProperty("javax.net.ssl.keyStore");
                String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");
                InputStream ksFin = new FileInputStream(keyStoreFilePath);
                char[] ksPassword = keyStorePassword.toCharArray();
                KeyStore ksKeys = KeyStore.getInstance("PKCS12");
                ksKeys.load(ksFin, ksPassword);
                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ksKeys, ksPassword);
            }
            // It is not secure to use SSLSocketFactory.getDefault().
            // We need to construct customized SSLSocketFactory with customized SSLContext.
            // SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            String trustStoreFilePath = System.getProperty("javax.net.ssl.trustStore");
            String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
            InputStream tsFin = new FileInputStream(trustStoreFilePath);
            char[] tsPassword = trustStorePassword.toCharArray();
            KeyStore ksTrust = KeyStore.getInstance("JKS");
            ksTrust.load(tsFin, tsPassword);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ksTrust);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf != null ? kmf.getKeyManagers() : null,
                tmf.getTrustManagers(), null);
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            SSLSocket socket =
                (SSLSocket) sslSocketFactory.createSocket(mServerName, mPort);
            // Do NOT use weak protocols and cipher suites. Configure this according to requirements.
            ((SSLSocket) socket).setEnabledProtocols(new String[] {"TLSv1.2"});
            // ((SSLSocket) socket).setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"});

            socket.setNeedClientAuth(mMutualAuthRequired);
            printSocketInfo(socket);

            socket.startHandshake();
            SSLSession session = ((SSLSocket) socket).getSession();
            printSessionInfo(session);

            // Create application-level connection
            AppConnection conn = new AppConnection(socket);

            HashMap<String,Object> props = new HashMap<String,Object>();
            // Request confidentiality
            props.put(Sasl.QOP, "auth-conf");

            // Create SaslClient to perform authentication
            SaslClient clnt = Sasl.createSaslClient(
                new String[]{MECH}, null, mService, mServerName, props, mCallbackHandler);

            if (clnt == null) {
                throw new Exception(
                    "Unable to find client implementation for " + MECH);
            }

            byte[] response;
            byte[] challenge;

            // Get initial response for authentication
            response = clnt.hasInitialResponse() ?
                clnt.evaluateChallenge(EMPTY) : EMPTY;

            // Send initial response to server
            AppConnection.AppReply reply =
                conn.send(AppConnection.AUTH_CMD, response);

            // Repeat until authentication terminates
            while (!clnt.isComplete() &&
                (reply.getStatus() == AppConnection.AUTH_INPROGRESS ||
                 reply.getStatus() == AppConnection.SUCCESS)) {

                // Evaluate challenge to generate response
                challenge = reply.getBytes();
                response = clnt.evaluateChallenge(challenge);

                if (reply.getStatus() == AppConnection.SUCCESS) {
                    if (response != null) {
                        throw new Exception("Protocol error interacting with SASL");
                    }
                    break;
                }

                // Send response to server and read server's next challenge
                reply = conn.send(AppConnection.AUTH_CMD, response);
            }

            // Check status of authentication
            if (clnt.isComplete() && reply.getStatus() == AppConnection.SUCCESS) {
                System.out.println("Client authenticated.");
            } else {
                throw new Exception("Authentication failed: " +
                    " connection status? " + reply.getStatus());
            }

            String qop = (String) clnt.getNegotiatedProperty(Sasl.QOP);
            System.out.println("Negotiated QOP: " + qop);

            // Try out security layer
            boolean sl = (qop.equals("auth-conf") || qop.equals("auth-int"));

            byte[] msg = "Hello There!".getBytes("UTF-8");
            System.out.println("Sending: " + new String(msg, "UTF-8"));

            byte[] encrypted = (sl ? clnt.wrap(msg, 0, msg.length) : msg);

            reply = conn.send(AppConnection.DATA_CMD, encrypted);

            if (reply.getStatus() == AppConnection.SUCCESS) {
                byte[] encryptedReply = reply.getBytes();

                byte[] clearReply = (sl ? clnt.unwrap(encryptedReply,
                    0, encryptedReply.length) : encryptedReply);

                System.out.println("Received: " + new String(clearReply, "UTF-8"));
            } else {
                System.out.println("Failed exchange: " + reply.getStatus());
            }

            conn.close();

            return null;

        }

        private void printSessionInfo(SSLSession session) throws Exception {
            Certificate[] cchan = session.getPeerCertificates();
            System.out.println("The certificates used by peer:");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (int i = 0; i < cchan.length; i++) {
                ByteArrayInputStream is = new ByteArrayInputStream(cchan[i].getEncoded());
                X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(is);
                System.out.println(x509Cert.getSubjectDN());
            }
            System.out.println("Peer host is " + session.getPeerHost());
            System.out.println("Cipher is " + session.getCipherSuite());
            System.out.println("Protocol is " + session.getProtocol());
            System.out.println("ID is " + new BigInteger(session.getId()));
            System.out.println("Session created on " + session.getCreationTime());
            System.out.println("Session accessed on " + session.getLastAccessedTime());
        }

        private void printSocketInfo(SSLSocket s) {
            System.out.println("Socket class: "+s.getClass());
            System.out.println("   Remote address = " +s.getInetAddress().toString());
            System.out.println("   Remote port = "+s.getPort());
            System.out.println("   Local socket address = " +s.getLocalSocketAddress().toString());
            System.out.println("   Local address = " +s.getLocalAddress().toString());
            System.out.println("   Local port = "+s.getLocalPort());
            System.out.println("   Need client authentication = " +s.getNeedClientAuth());
            SSLSession ss = s.getSession();
            System.out.println("   Cipher suite = "+ss.getCipherSuite());
            System.out.println("   Protocol = "+ss.getProtocol());
        }
    }
}
