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
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsRSASigner;

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

    private static final String PATH_TO_JKS = "rsa2048.jks";

    private static final String JKS_PASSWORD = "password";

    private static final String ALIAS = "1";

    private static final int PORT = 4433;

    private final int port;

    private KeyPair rsaKeyPair;

    private Certificate rsaCert;

    private KeyPair ecKeyPair;

    private Certificate ecCert;

    private boolean shutdown;

    private ServerSocket serverSocket;
    private KeyStore keyStore;
    private String alias;

    public BouncyCastleTLSServer(int port) {
        this.port = port;
    }

    public void addRsaKey(KeyStore keyStore, String password, String alias) throws IOException,
            KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException, UnrecoverableKeyException {
//        rsaCert = loadTLSCertificate(keyStore, alias, );
        this.keyStore = keyStore;
        this.alias = alias;
        rsaKeyPair = getKeyPair(keyStore, alias, password.toCharArray());
    }

    public void addEcKey(KeyStore keyStore, String password, String alias) throws IOException,
            KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException, UnrecoverableKeyException {
//        ecCert = loadTLSCertificate(keyStore, alias);
        ecKeyPair = getKeyPair(keyStore, alias, password.toCharArray());
    }

    public void createServerSocket() throws IOException {
        serverSocket = new ServerSocket(port);
    }

    public static void main(String[] args) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Security.insertProviderAt(provider, 1);
        System.setProperty("java.security.debug", "ssl");
        String rsaPath, ecPath = null;
        String rsaPassword, ecPassword = null;
        String rsaAlias, ecAlias = null;
        int port;

        switch (args.length) {
            case 4:
            case 7:
                port = Integer.parseInt(args[0]);
                rsaPath = args[1];
                rsaPassword = args[2];
                rsaAlias = args[3];
                if (args.length == 7) {
                    ecPath = args[4];
                    ecPassword = args[5];
                    ecAlias = args[6];
                }
                break;
            case 0:
                rsaPath = PATH_TO_JKS;
                rsaPassword = JKS_PASSWORD;
                rsaAlias = ALIAS;
                port = PORT;
                break;
            default:
                System.out.println("Usage (run with): java -jar [name].jar [port] [rsa-jks-path] "
                        + "[rsa-password] [rsa-alias] [ec-jks-path] [ec-password] [ec-alias]");
                return;
        }

        KeyStore ksRSA = KeyStore.getInstance("JKS");
        ksRSA.load(new FileInputStream(rsaPath), rsaPassword.toCharArray());

        BouncyCastleTLSServer server = new BouncyCastleTLSServer(port);
        server.addRsaKey(ksRSA, rsaPassword, rsaAlias);
        if (ecAlias != null) {
            KeyStore ksEC = KeyStore.getInstance("JKS");
            ksEC.load(new FileInputStream(ecPath), ecPassword.toCharArray());
            server.addEcKey(ksEC, ecPassword, ecAlias);
        }
        server.createServerSocket();
        server.start();
    }

    public void start() throws IOException {
        AsymmetricKeyParameter key = PrivateKeyFactory.createKey(rsaKeyPair.getPrivate().getEncoded());
        while (!shutdown) {
            try {
                LOGGER.info("Listening on port " + port + "...\n");
                final Socket socket = serverSocket.accept();

                DefaultTlsServer server = new DefaultTlsServer(new BcTlsCrypto(new SecureRandom())) {
                    @Override
                    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
                        BcTlsRSASigner signer = new BcTlsRSASigner(new BcTlsCrypto(new SecureRandom()), (RSAKeyParameters) key);
                        try {
                            return new DefaultTlsCredentialedSigner(new TlsCryptoParameters(context), signer, loadTLSCertificate(keyStore, alias, context), new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa));
                        } catch (KeyStoreException e) {
                            e.printStackTrace();
                        } catch (CertificateEncodingException e) {
                            e.printStackTrace();
                        }
                        return null;
                    }

                    @Override
                    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() throws IOException {
//                         TODO PrivateKeyFactory possibly old api?
//                        return new JceDefaultTlsCredentialedDecryptor(context.getCrypto(), rsaCert, PrivateKeyFactory.createKey(rsaKeyPair.getPrivate().getEncoded()));
                        try {
                            return new BcDefaultTlsCredentialedDecryptor(new BcTlsCrypto(new SecureRandom()), loadTLSCertificate(keyStore, alias, context), key);
                        } catch (KeyStoreException e) {
                            e.printStackTrace();
                        } catch (CertificateEncodingException e) {
                            e.printStackTrace();
                        }
                        return null;
                    }

                    @Override
                    public BcDefaultTlsCredentialedDecryptor getCredentials() throws IOException {
                        switch (selectedCipherSuite) {
                            case CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
                            case CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
                            case CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5:
                            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
                            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
                            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
                            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
                            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
                            case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                            case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
                            case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                            case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                                try {
                                    return new BcDefaultTlsCredentialedDecryptor(new BcTlsCrypto(new SecureRandom()), loadTLSCertificate(keyStore, alias, context), key);
                                } catch (KeyStoreException e) {
                                    e.printStackTrace();
                                } catch (CertificateEncodingException e) {
                                    e.printStackTrace();
                                }

                                return null;
//                                return new DefaultTlsSignerCredentials(context, ecCert, PrivateKeyFactory.createKey(ecKeyPair.getPrivate().getEncoded()));
                            default:
                                return null;
                        }
                    }

                    @Override
                    protected int[] getCipherSuites() {
                        int[] defaultCiphers = new int[0];//super.getCipherSuites();
                        int[] newCiphers = new int[]{
                        CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
                        CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                        CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                        CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_NULL_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                        CipherSuite.TLS_RSA_WITH_RC4_128_SHA};
                        int[] ciphers = new int[defaultCiphers.length + newCiphers.length];
                        System.arraycopy(defaultCiphers, 0, ciphers, 0, defaultCiphers.length);
                        System.arraycopy(newCiphers, 0, ciphers, defaultCiphers.length, newCiphers.length);

                        return ciphers;
                    }
                };
                TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(
                        socket.getInputStream(), socket.getOutputStream());
                tlsServerProtocol.accept(server);
                ConnectionHandler ch = new ConnectionHandler(tlsServerProtocol);
                Thread t = new Thread(ch);
                t.start();
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
    
    /**
     * Loads a certificate from a keystore
     *
     * @param keyStore
     * @param alias
     * @return
     * @throws KeyStoreException
     * @throws CertificateEncodingException
     * @throws IOException
     */
    public static Certificate loadTLSCertificate(KeyStore keyStore, String alias, TlsContext context)
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

    public static KeyPair getKeyPair(final KeyStore keystore, final String alias, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password);
        java.security.cert.Certificate cert = keystore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, privateKey);
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
