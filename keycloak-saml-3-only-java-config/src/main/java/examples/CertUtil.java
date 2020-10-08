package examples;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.util.Assert;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import static org.springframework.security.saml2.core.Saml2X509Credential.decryption;
import static org.springframework.security.saml2.core.Saml2X509Credential.signing;
import static org.springframework.security.saml2.core.Saml2X509Credential.verification;

public class CertUtil {

    public static Saml2X509Credential getSigningCredential(String privateKeyLocation, String certificateLocation) {
        return signing(
            readPrivateKey(new ClassPathResource(privateKeyLocation)),
            readCertificate(new ClassPathResource(certificateLocation))
        );
    }

    public static Saml2X509Credential getEncryptionCredential(String privateKeyLocation, String certificateLocation) {
        return decryption(
            readPrivateKey(new ClassPathResource(privateKeyLocation)),
            readCertificate(new ClassPathResource(certificateLocation))
        );
    }

    public static Saml2X509Credential getVerificationCredential(String certificateLocation) {
        return verification(
            readCertificate(new ClassPathResource(certificateLocation))
        );
    }

    private static RSAPrivateKey readPrivateKey(Resource location) {
        Assert.state(location != null, "No private key location specified");
        Assert.state(location.exists(), "Private key location '" + location + "' does not exist");
        try (final InputStream inputStream = location.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(inputStream);
        }
        catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static X509Certificate readCertificate(Resource location) {
        Assert.state(location != null, "No certificate location specified");
        Assert.state(location.exists(), "Certificate  location '" + location + "' does not exist");
        try (final InputStream inputStream = location.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
        }
        catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
