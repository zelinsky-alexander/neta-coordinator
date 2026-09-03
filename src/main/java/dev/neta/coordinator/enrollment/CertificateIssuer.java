package dev.neta.coordinator.enrollment;

import dev.neta.coordinator.config.CoordinatorProperties;
import dev.neta.coordinator.protocol.ProtocolException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

@Service
public final class CertificateIssuer {
    private final CoordinatorProperties properties;
    private final SecureRandom random = new SecureRandom();

    public CertificateIssuer(CoordinatorProperties properties) { this.properties = properties; }

    public IssuedCertificate issue(String agentId, String csrPem) {
        if (csrPem == null || csrPem.isBlank()) throw ProtocolException.badRequest("csr_pem is required");
        var config = properties.enrollment();
        if (config.issuerKeyStore() == null || config.issuerKeyStore().isBlank()
                || config.issuerKeyStorePassword() == null || config.issuerKeyStorePassword().isBlank()
                || config.fleetCaFile() == null || config.fleetCaFile().isBlank())
            throw new IllegalStateException("enrollment certificate issuer is not configured");
        try {
            IssuerMaterial issuer = loadIssuer(config);
            PKCS10CertificationRequest csr = parseCsr(csrPem);
            if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo())))
                throw ProtocolException.badRequest("CSR signature is invalid");
            var publicKey = new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());
            Instant now = Instant.now();
            Instant notBefore = now.minusSeconds(300);
            Instant notAfter = now.plus(config.certificateTtl());
            BigInteger serial = new BigInteger(160, random).abs().add(BigInteger.ONE);
            X500Name subject = new X500Name("CN=" + agentId + ",O=NETA");
            var builder = new JcaX509v3CertificateBuilder(issuer.certificate(), serial,
                    Date.from(notBefore), Date.from(notAfter), subject, publicKey);
            var extensions = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
            builder.addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(publicKey));
            builder.addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(issuer.certificate()));
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(issuer.privateKey())).build(issuer.privateKey());
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
            certificate.verify(issuer.certificate().getPublicKey());
            String certificatePem = toPem(certificate);
            String issuerPem = toPem(issuer.certificate());
            String chainPem = certificatePem + issuerPem;
            String fleetCaPem = Files.readString(Path.of(config.fleetCaFile()));
            String fingerprint = "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
            return new IssuedCertificate(certificatePem, chainPem, issuerPem, fleetCaPem, fingerprint,
                    certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        } catch (ProtocolException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("failed to issue agent certificate", e); }
    }

    private static PKCS10CertificationRequest parseCsr(String csrPem) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            Object value = parser.readObject();
            if (!(value instanceof PKCS10CertificationRequest csr) || parser.readObject() != null)
                throw ProtocolException.badRequest("csr_pem must contain exactly one PKCS#10 request");
            return csr;
        }
    }

    private static IssuerMaterial loadIssuer(CoordinatorProperties.Enrollment config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(config.issuerKeyStoreType());
        char[] password = config.issuerKeyStorePassword().toCharArray();
        try (var input = Files.newInputStream(Path.of(config.issuerKeyStore()))) { keyStore.load(input, password); }
        String alias = config.issuerKeyAlias();
        if (!keyStore.isKeyEntry(alias)) throw new IllegalStateException("issuer key alias not found: " + alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        if (privateKey == null || certificate == null) throw new IllegalStateException("issuer key store does not contain a private key and certificate");
        if (certificate.getBasicConstraints() < 0) throw new IllegalStateException("configured enrollment issuer certificate is not a CA certificate");
        return new IssuerMaterial(privateKey, certificate);
    }

    private static String signatureAlgorithm(PrivateKey key) {
        return switch (key.getAlgorithm().toUpperCase()) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            default -> throw new IllegalStateException("unsupported issuer private key algorithm: " + key.getAlgorithm());
        };
    }

    private static String toPem(Object value) throws IOException {
        StringWriter output = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(output)) { writer.writeObject(value); }
        return output.toString();
    }

    private record IssuerMaterial(PrivateKey privateKey, X509Certificate certificate) {}

    public record IssuedCertificate(String certificatePem, String certificateChainPem,
            String issuerCertificatePem, String fleetCaPem, String certificateSha256,
            Instant notBefore, Instant notAfter) {}
}
