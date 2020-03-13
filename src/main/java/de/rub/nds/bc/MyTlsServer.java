package de.rub.nds.bc;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRSASigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor;

import java.io.IOException;
import java.security.KeyPair;

public class MyTlsServer extends DefaultTlsServer {
    JcaTlsCrypto jcaTlsCrypto;
    KeyPair rsaKeyPair;
    Certificate certificate;

    public MyTlsServer(TlsCrypto crypto, KeyPair rsaKeyPair, Certificate certificate) {
        super(crypto);

        this.jcaTlsCrypto = (JcaTlsCrypto) crypto;
        this.rsaKeyPair = rsaKeyPair;
        this.certificate = certificate;
    }

    @Override
    protected TlsCredentialedSigner getRSASignerCredentials() {
        JcaTlsRSASigner signer = new JcaTlsRSASigner(jcaTlsCrypto, rsaKeyPair.getPrivate());

        return new DefaultTlsCredentialedSigner(new TlsCryptoParameters(context), signer, certificate, new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa));
    }

    @Override
    protected TlsCredentialedDecryptor getRSAEncryptionCredentials() {
        return new JceDefaultTlsCredentialedDecryptor(jcaTlsCrypto, certificate, rsaKeyPair.getPrivate());
    }

    @Override
    public JceDefaultTlsCredentialedDecryptor getCredentials() {
        switch (selectedCipherSuite) {
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                return new JceDefaultTlsCredentialedDecryptor(jcaTlsCrypto, certificate, rsaKeyPair.getPrivate());
            default:
                return null;
        }
    }


    @Override
    public void notifyHandshakeComplete() throws IOException {
        super.notifyHandshakeComplete();
        byte[] secretBytes = getMasterSecret().extract();
        StringBuffer hexString = new StringBuffer();
        for (int i=0;i<secretBytes.length;i++) {
            hexString.append(Integer.toHexString(0xFF & secretBytes[i]));
        }
        System.out.println("Connection opened");
        System.out.println("Master secret: " + hexString);
        System.out.println("PRF algorithm: " + context.getSecurityParameters().getPrfAlgorithm());
    }

    @Override
    protected int[] getCipherSuites() {
        int[] defaultCiphers = new int[0];//super.getCipherSuites();
        int[] newCiphers = new int[]{
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256
        };
        int[] ciphers = new int[defaultCiphers.length + newCiphers.length];
        System.arraycopy(defaultCiphers, 0, ciphers, 0, defaultCiphers.length);
        System.arraycopy(newCiphers, 0, ciphers, defaultCiphers.length, newCiphers.length);

        return ciphers;
    }

    public TlsSecret getMasterSecret() {
        return context.getSecurityParameters().getMasterSecret();
    }
}
