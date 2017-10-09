import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class SimpleEchoServer {
    private final int mPort;
    private boolean mStopped;
    private ServerSocketFactory mServerSocketFactory;
    private ServerSocket mServerSocket;
    private List<Thread> mWorkerThreads = new ArrayList<>();

    public SimpleEchoServer(int port) {
        mPort = port;
        mStopped = true;
    }
    public void start() throws Exception {
        if (mStopped) {
            mServerSocketFactory = SSLServerSocketFactory.getDefault();
            mServerSocket = mServerSocketFactory.createServerSocket(mPort);
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
