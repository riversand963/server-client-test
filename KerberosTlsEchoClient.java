import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivilegedExceptionAction;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class KerberosTlsEchoClient {
    public static void main(String[] args) throws Exception {
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        boolean mutualAuthRequired = Boolean.parseBoolean(args[2]);
        KerberosTlsEchoClientAction action = new KerberosTlsEchoClientAction(host, port, mutualAuthRequired);
        Jaas.loginAndAction("client", action);
    }

    private static void printSessionInfo(SSLSession session) throws Exception {
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

    private static void printSocketInfo(SSLSocket s) {
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

    private static class KerberosTlsEchoClientAction implements PrivilegedExceptionAction<Object> {
        private String mHost;
        private int mPort;
        private boolean mMutualAuthRequired;

        public KerberosTlsEchoClientAction(String host, int port, boolean mutualAuthRequired) {
            mHost = host;
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
                (SSLSocket) sslSocketFactory.createSocket(mHost, mPort);
            // Do NOT use weak protocols and cipher suites. Configure this according to requirements.
            socket.setEnabledProtocols(new String[] {"TLSv1.2"});
            // ((SSLSocket) socket).setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"});

            socket.setNeedClientAuth(mMutualAuthRequired);
            printSocketInfo(socket);

            socket.startHandshake();

            SSLSession session = socket.getSession();
            printSessionInfo(session);

            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            PrintStream out = System.out;

            BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            String line;
            String response;
            while ((line = in.readLine()) != null) {
                bufferedWriter.write(line, 0, line.length());
                bufferedWriter.newLine();
                bufferedWriter.flush();

                response = bufferedReader.readLine();
                out.println(response);
            }
            bufferedWriter.close();
            bufferedReader.close();
            socket.close();

            return null;
        }
    }
}

