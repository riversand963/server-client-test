import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class SimpleEchoServer {
    private final int mPort;
    private boolean mMutualAuthRequired;
    private boolean mStopped;
    private ServerSocketFactory mServerSocketFactory;
    private ServerSocket mServerSocket;
    private List<Thread> mWorkerThreads = new ArrayList<>();

    public SimpleEchoServer(int port, boolean mutualAuthRequired) {
        mPort = port;
        mMutualAuthRequired = mutualAuthRequired;
        mStopped = true;
    }

    public void start() throws Exception {
        if (mStopped) {
            // SSLServerSocketFactory.getDefault() is not secure. To gain more security,
            // we need to construct customized SSLServerSocketFactory based on customized SSLContext.
            // mServerSocketFactory = SSLServerSocketFactory.getDefault();
            String keyStoreFilePath = System.getProperty("javax.net.ssl.keyStore");
            String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");
            InputStream ksFin = new FileInputStream(keyStoreFilePath);
            char[] ksPassword = keyStorePassword.toCharArray();
            KeyStore ksKeys = KeyStore.getInstance("PKCS12");
            ksKeys.load(ksFin, ksPassword);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ksKeys, ksPassword);

            TrustManagerFactory tmf = null;
            if (mMutualAuthRequired) {
                String trustStoreFilePath = System.getProperty("javax.net.ssl.trustStore");
                String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
                InputStream tsFin = new FileInputStream(trustStoreFilePath);
                char[] tsPassword = trustStorePassword.toCharArray();
                KeyStore ksTrust = KeyStore.getInstance("JKS");
                ksTrust.load(tsFin, tsPassword);
                tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(ksTrust);
            }

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(),
                tmf != null ? tmf.getTrustManagers() : null, null);

            mServerSocketFactory = sslContext.getServerSocketFactory();
            mServerSocket = mServerSocketFactory.createServerSocket(mPort);

            // Need client auth
            ((SSLServerSocket) mServerSocket).setNeedClientAuth(mMutualAuthRequired);

            // Do NOT use weak protocols and cipher suites. Configure this according to requirements.
            ((SSLServerSocket) mServerSocket).setEnabledProtocols(new String[] {"SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"});
            // ((SSLServerSocket) mServerSocket).setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"});

            // Start the server
            mStopped = false;
        }
    }

    public void serve() throws Exception {
        if (mStopped) {
            System.out.println("Server not started.");
            return;
        }
        while (true) {
            Socket socket = mServerSocket.accept();
            SSLSession session = ((SSLSocket) socket).getSession();
            printSessionInfo(session);
            Worker worker = new Worker(socket);
            Thread thread = new Thread(worker);
            mWorkerThreads.add(thread);
            thread.start();
        }
    }

    public void stop() throws Exception {
        if (!mStopped) {
            mServerSocket.close();
        }
    }

    private void printSessionInfo(SSLSession session) throws Exception {
        Certificate[] cchan = session.getLocalCertificates();
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
        System.out.println("Session created in " + session.getCreationTime());
        System.out.println("Session accessed in " + session.getLastAccessedTime());
    }

    private static class Worker implements Runnable {
        private Socket mSocket;
        public Worker(Socket socket) {
            mSocket = socket;
        }
        public void run() {
            String inputLine;
            try {
                BufferedReader bufferedReader =
                    new BufferedReader(new InputStreamReader(mSocket.getInputStream()));
                BufferedWriter bufferedWriter =
                    new BufferedWriter(new OutputStreamWriter(mSocket.getOutputStream()));

                while ((inputLine = bufferedReader.readLine()) != null) {
                    System.out.println(inputLine);
                    bufferedWriter.write(inputLine, 0, inputLine.length());
                    bufferedWriter.newLine();
                    bufferedWriter.flush();
                }

                bufferedReader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
