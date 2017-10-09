import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SimpleEchoClient {
    public static void main(String[] args) throws Exception {
        String hostName = args[0];
        int port = Integer.parseInt(args[1]);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in));
        PrintStream out = System.out;
        SSLSocketFactory sslSocketFactory =
            (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket =
            (SSLSocket) sslSocketFactory.createSocket(hostName, port);
        printSocketInfo(socket);

        socket.startHandshake();

        SSLSession session = ((SSLSocket) socket).getSession();
        printSessionInfo(session);

        BufferedWriter bufferedWriter =
            new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
        BufferedReader bufferedReader =
            new BufferedReader(new InputStreamReader(socket.getInputStream()));
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
}
