package dev.neta.coordinator.security;

import jakarta.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
public final class PeerCertificateService {
    private static final String CERT_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    public Optional<PeerCertificate> peerCertificate(HttpServletRequest request) {
        Object value = request.getAttribute(CERT_ATTRIBUTE);
        if (!(value instanceof X509Certificate[] chain) || chain.length == 0) return Optional.empty();
        X509Certificate certificate = chain[0];
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            return Optional.of(new PeerCertificate(
                    "sha256:" + HexFormat.of().formatHex(digest),
                    certificate.getNotBefore().toInstant(),
                    certificate.getNotAfter().toInstant()));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("unable to encode peer certificate", e);
        }
    }

    public Optional<String> sha256Fingerprint(HttpServletRequest request) {
        return peerCertificate(request).map(PeerCertificate::sha256Fingerprint);
    }

    public record PeerCertificate(String sha256Fingerprint, Instant notBefore, Instant notAfter) {}
}
