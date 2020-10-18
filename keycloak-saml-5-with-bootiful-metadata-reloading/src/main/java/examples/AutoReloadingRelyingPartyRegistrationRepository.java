package examples;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties.Identityprovider.Verification;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties.Registration;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties.Registration.Signing;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.Builder;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

@Component
public class AutoReloadingRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutoReloadingRelyingPartyRegistrationRepository.class);

    private final Saml2RelyingPartyProperties properties;

    private final Map<String, RelyingPartyRegistration> registrations = Collections.synchronizedMap(new LinkedHashMap<>());

    public AutoReloadingRelyingPartyRegistrationRepository(Saml2RelyingPartyProperties properties) {
        this.properties = properties;
        refreshRelyingPartyRegistrations();
    }

    // ========================================================================================================
    // CUSTOM CODE
    // ========================================================================================================

    @Override
    public Iterator<RelyingPartyRegistration> iterator() {
        return new ArrayList<>(registrations.values()).iterator();
    }

    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        return registrations.get(registrationId);
    }

    @Scheduled(fixedDelayString = "${additional-saml-configuration.metadata-refresh-interval}", initialDelay = 10_000)
    private void refreshRelyingPartyRegistrations() {

        LOGGER.debug("refreshRelyingPartyRegistrations");

        properties.getRegistration().forEach((registrationId, registrationProperties) -> {

            try {
                registrations.put(registrationId, asRegistration(registrationId, registrationProperties));
            }
            catch (Exception e) {
                LOGGER.warn("Could not refresh RelyingPartyRegistration configuration.", e);
            }
        });
    }

    // ========================================================================================================
    // COPY PASTE FROM Saml2RelyingPartyRegistrationConfiguration
    // ========================================================================================================

    private RelyingPartyRegistration asRegistration(String id, Registration properties) {
        boolean usingMetadata = StringUtils.hasText(properties.getIdentityprovider().getMetadataUri());
        Builder builder = (usingMetadata) ? RelyingPartyRegistrations
            .fromMetadataLocation(properties.getIdentityprovider().getMetadataUri()).registrationId(id)
            : RelyingPartyRegistration.withRegistrationId(id);
        builder.assertionConsumerServiceLocation(properties.getAcs().getLocation());
        builder.assertionConsumerServiceBinding(properties.getAcs().getBinding());
        builder.assertingPartyDetails(mapIdentityProvider(properties, usingMetadata));
        builder.signingX509Credentials((credentials) -> properties.getSigning().getCredentials().stream()
                                                                  .map(this::asSigningCredential).forEach(credentials::add));
        builder.decryptionX509Credentials((credentials) -> properties.getDecryption().getCredentials().stream()
                                                                     .map(this::asDecryptionCredential).forEach(credentials::add));
        builder.assertingPartyDetails((details) -> details
            .verificationX509Credentials((credentials) -> properties.getIdentityprovider().getVerification()
                                                                    .getCredentials().stream().map(this::asVerificationCredential).forEach(credentials::add)));
        builder.entityId(properties.getEntityId());
        RelyingPartyRegistration registration = builder.build();
        boolean signRequest = registration.getAssertingPartyDetails().getWantAuthnRequestsSigned();
        validateSigningCredentials(properties, signRequest);
        return registration;
    }

    private Consumer<AssertingPartyDetails.Builder> mapIdentityProvider(Registration properties,
                                                                        boolean usingMetadata) {
        PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
        Saml2RelyingPartyProperties.Identityprovider identityprovider = properties.getIdentityprovider();
        return (details) -> {
            map.from(identityprovider::getEntityId).to(details::entityId);
            map.from(identityprovider.getSinglesignon()::getBinding).to(details::singleSignOnServiceBinding);
            map.from(identityprovider.getSinglesignon()::getUrl).to(details::singleSignOnServiceLocation);
            map.from(identityprovider.getSinglesignon()::isSignRequest).when((signRequest) -> !usingMetadata)
               .to(details::wantAuthnRequestsSigned);
        };
    }

    private void validateSigningCredentials(Registration properties, boolean signRequest) {
        if (signRequest) {
            Assert.state(!properties.getSigning().getCredentials().isEmpty(),
                         "Signing credentials must not be empty when authentication requests require signing.");
        }
    }

    private Saml2X509Credential asSigningCredential(Signing.Credential properties) {
        RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
    }

    private Saml2X509Credential asDecryptionCredential(Saml2RelyingPartyProperties.Decryption.Credential properties) {
        RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
    }

    private Saml2X509Credential asVerificationCredential(Verification.Credential properties) {
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
                                       Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
    }

    private RSAPrivateKey readPrivateKey(Resource location) {
        Assert.state(location != null, "No private key location specified");
        Assert.state(location.exists(), () -> "Private key location '" + location + "' does not exist");
        try (InputStream inputStream = location.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(inputStream);
        }
        catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    private X509Certificate readCertificate(Resource location) {
        Assert.state(location != null, "No certificate location specified");
        Assert.state(location.exists(), () -> "Certificate  location '" + location + "' does not exist");
        try (InputStream inputStream = location.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
        }
        catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }
}
