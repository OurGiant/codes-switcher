package com.ourgiant.crypt.crypto.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Reads PKCS#12 (.p12/.pfx) and JKS keystores and lists their certificates. */
public final class KeyStoreReader {

    public enum Kind { PRIVATE_KEY, TRUSTED_CERT, SECRET_KEY }

    public record Entry(String alias, Kind kind, List<X509Certificate> chain) {
    }

    /** Thrown when the password is wrong, so the UI can ask again. */
    public static final class WrongPasswordException extends IOException {
        public WrongPasswordException() {
            super("Wrong keystore password");
        }
    }

    private KeyStoreReader() {
    }

    /** JKS files start with 0xFEEDFEED; PKCS#12 is a DER SEQUENCE. */
    public static String detectType(byte[] data) {
        if (data.length >= 4 && (data[0] & 0xff) == 0xFE && (data[1] & 0xff) == 0xED
                && (data[2] & 0xff) == 0xFE && (data[3] & 0xff) == 0xED) {
            return "JKS";
        }
        if (data.length > 0 && (data[0] & 0xff) == 0x30) {
            return "PKCS12";
        }
        return null;
    }

    public static List<Entry> read(byte[] data, char[] password) throws IOException {
        String type = detectType(data);
        if (type == null) {
            throw new IOException("Not a PKCS#12 or JKS keystore");
        }
        try {
            KeyStore ks = KeyStore.getInstance(type);
            ks.load(new ByteArrayInputStream(data), password);
            List<Entry> entries = new ArrayList<>();
            for (String alias : Collections.list(ks.aliases())) {
                Kind kind = ks.isKeyEntry(alias)
                        ? (ks.getCertificateChain(alias) != null ? Kind.PRIVATE_KEY : Kind.SECRET_KEY)
                        : Kind.TRUSTED_CERT;
                List<X509Certificate> chain = new ArrayList<>();
                Certificate[] certs = ks.getCertificateChain(alias);
                if (certs == null && ks.getCertificate(alias) != null) {
                    certs = new Certificate[]{ks.getCertificate(alias)};
                }
                if (certs != null) {
                    for (Certificate c : certs) {
                        if (c instanceof X509Certificate x) {
                            chain.add(x);
                        }
                    }
                }
                entries.add(new Entry(alias, kind, chain));
            }
            entries.sort((a, b) -> a.alias().compareToIgnoreCase(b.alias()));
            return entries;
        } catch (IOException e) {
            if (e.getCause() instanceof UnrecoverableKeyException
                    || String.valueOf(e.getMessage()).toLowerCase().contains("password")) {
                throw new WrongPasswordException();
            }
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IOException("Couldn't read keystore: " + e.getMessage(), e);
        }
    }
}
