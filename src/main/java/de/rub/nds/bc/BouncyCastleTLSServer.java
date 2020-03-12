package de.rub.nds.bc;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRSASigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;

/**
 * Basic Bouncy Castle TLS server. Do not use for real applications, just a demo
 * server for security testing purposes.
 *
 * Works for BC 1.50 and higher.
 * 
 * Since BC 1.57 it is also possible to use a newer TLS server version 
 * (org.bouncycastle.tls.DefaultTlsServer). But it is not available in versions
 * 1.50 - 1.55
 *
 * From:
 * https://stackoverflow.com/questions/18065170/how-do-i-do-tls-with-bouncycastle
 * and
 * https://www.programcreek.com/java-api-examples/index.php?source_dir=usc-master/usc-channel-impl/src/main/java/org/opendaylight/usc/crypto/dtls/DtlsUtils.java
 * and https://github.com/RUB-NDS/TLS-Attacker
 *
 */
public class BouncyCastleTLSServer {

    private static final Logger LOGGER = LogManager.getLogger(BouncyCastleTLSServer.class);

    private static final String PATH_TO_JKS = "keystore.jks";

    private static final String JKS_PASSWORD = "changeit";

    private static final String ALIAS = "server-alias";

    private static final int PORT = 8888;

    private final int port;

    private KeyPair rsaKeyPair;

    private Certificate rsaCert;

    private boolean shutdown;

    private ServerSocket serverSocket;

    public BouncyCastleTLSServer(int port) {
        this.port = port;
    }

    public void addRsaKey(KeyStore keyStore, String password, String alias) throws IOException,
            KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException, UnrecoverableKeyException {
        rsaKeyPair = getKeyPair(keyStore, alias, password.toCharArray());
        rsaCert = loadTLSCertificate(keyStore, alias);
    }

    public void createServerSocket() throws IOException {
        serverSocket = new ServerSocket(port);
    }

    public static void main(String[] args) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Security.insertProviderAt(provider, 1);
        System.setProperty("java.security.debug", "ssl");
        String rsaPath = null;
        String rsaPassword = null;
        String rsaAlias = null;
        int port;

        switch (args.length) {
            case 4:
                port = Integer.parseInt(args[0]);
                rsaPath = args[1];
                rsaPassword = args[2];
                rsaAlias = args[3];
                break;
            case 0:
                rsaPath = PATH_TO_JKS;
                rsaPassword = JKS_PASSWORD;
                rsaAlias = ALIAS;
                port = PORT;
                break;
            default:
                System.out.println("Usage (run with): java -jar [name].jar [port] [rsa-jks-path] "
                        + "[rsa-password] [rsa-alias]");
                return;
        }

        KeyStore ksRSA = KeyStore.getInstance("JKS");
        ksRSA.load(new FileInputStream(rsaPath), rsaPassword.toCharArray());

        BouncyCastleTLSServer server = new BouncyCastleTLSServer(port);
        server.addRsaKey(ksRSA, rsaPassword, rsaAlias);
        server.createServerSocket();
        server.start();
    }

    public void start() throws IOException {
        TlsCrypto tlsCrypto=(new JcaTlsCryptoProvider()).create(new SecureRandom());
        if(!(tlsCrypto instanceof JcaTlsCrypto))
            throw new TlsCryptoException("Client #19", new ClassCastException("tlsCrypto !instanceof JcaTlsCrypto"));
        JcaTlsCrypto jcaTlsCrypto=(JcaTlsCrypto)tlsCrypto;
        while (!shutdown) {
            try {
                LOGGER.info("Listening on port " + port + "...\n");
                final Socket socket = serverSocket.accept();

                MyTlsServer server = new MyTlsServer(jcaTlsCrypto, rsaKeyPair, rsaCert);
                TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(
                        socket.getInputStream(), socket.getOutputStream());
                tlsServerProtocol.accept(server);
                ConnectionHandler ch = new ConnectionHandler(tlsServerProtocol);
                Thread t = new Thread(ch);
                t.start();

                System.out.println(server.getMasterSecret());

            } catch (IOException | NullPointerException ex) {
                LOGGER.info(ex.getLocalizedMessage(), ex);
            }
        }

        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ex) {
            LOGGER.info(ex.getLocalizedMessage(), ex);
        }
        LOGGER.info("Shutdown complete");
    }

    public static KeyPair getKeyPair(final KeyStore keystore, final String alias, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password);
        java.security.cert.Certificate cert = keystore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static Certificate loadTLSCertificate(KeyStore keyStore, String alias)
            throws KeyStoreException, CertificateEncodingException, IOException {
        java.security.cert.Certificate sunCert = keyStore.getCertificate(alias);
        byte[] certBytes = sunCert.getEncoded();

        ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
        TlsCertificate c = new BcTlsCertificate(new BcTlsCrypto(new SecureRandom()), certBytes);
        TlsCertificate[] certs = new TlsCertificate[1];
        certs[0] = c;

        return new Certificate(certs);
    }

//    static Certificate loadCertificateChain(String[] resources) throws IOException {
//        org.bouncycastle.asn1.x509.Certificate[] chain = new org.bouncycastle.asn1.x509.Certificate[resources.length];
//        for (int i = 0; i < resources.length; ++i) {
//            chain[i] = loadCertificateResource(resources[i]);
//        }
//        return new Certificate(chain);
//    }
//
//    static org.bouncycastle.asn1.x509.Certificate loadCertificateResource(String resource) throws IOException {
//        PemObject pem = loadPemResource(resource);
//        if (pem.getType().endsWith("CERTIFICATE")) {
//            return org.bouncycastle.asn1.x509.Certificate.getInstance(pem.getContent());
//        }
//        throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
//    }
//
//    static PemObject loadPemResource(String resource) throws IOException {
//        // InputStream s = TlsTestUtils.class.getResourceAsStream(resource); 
//        InputStream s = new FileInputStream(resource);
//        PemReader p = new PemReader(new InputStreamReader(s));
//        PemObject o = p.readPemObject();
//        p.close();
//        return o;
//    }
//
}
