package examples;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.util.Collections;
import java.util.Iterator;

import static examples.CertUtil.getEncryptionCredential;
import static examples.CertUtil.getSigningCredential;

public class AutoReloadingSingleRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutoReloadingSingleRelyingPartyRegistrationRepository.class);

    private final String registrationId;
    private final String identityproviderMetadataUri;
    private final String relyingPartyEntityId;
    private final Saml2MessageBinding assertionConsumerServiceBinding;
    private final Resource signingCredentialPrivateKeyLocation;
    private final Resource signingCredentialCertificateLocation;
    private final Resource encryptionCredentialPrivateKeyLocation;
    private final Resource encryptionCredentialCertificateLocation;

    private RelyingPartyRegistration relyingPartyRegistration;

    public AutoReloadingSingleRelyingPartyRegistrationRepository(
        String registrationId,
        String identityproviderMetadataUri,
        String relyingPartyEntityId,
        Saml2MessageBinding assertionConsumerServiceBinding,
        Resource signingCredentialPrivateKeyLocation,
        Resource signingCredentialCertificateLocation,
        Resource encryptionCredentialPrivateKeyLocation,
        Resource encryptionCredentialCertificateLocation
    ) {

        this.registrationId = registrationId;

        this.identityproviderMetadataUri = identityproviderMetadataUri;

        this.relyingPartyEntityId = relyingPartyEntityId;
        this.assertionConsumerServiceBinding = assertionConsumerServiceBinding;

        this.signingCredentialPrivateKeyLocation = signingCredentialPrivateKeyLocation;
        this.signingCredentialCertificateLocation = signingCredentialCertificateLocation;
        this.encryptionCredentialPrivateKeyLocation = encryptionCredentialPrivateKeyLocation;
        this.encryptionCredentialCertificateLocation = encryptionCredentialCertificateLocation;

        refreshRelyingPartyRegistration();
    }

    @Override
    public RelyingPartyRegistration findByRegistrationId(String id) {
        return relyingPartyRegistration;
    }

    @Scheduled(fixedDelayString = "${relying-party-registration.refresh-delay}", initialDelay = 10_000)
    private void refreshRelyingPartyRegistration() {
        try {

            LOGGER.debug("refreshRelyingPartyRegistration");

            this.relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(identityproviderMetadataUri)
                .registrationId(registrationId)
                .entityId(relyingPartyEntityId)
                .assertionConsumerServiceBinding(assertionConsumerServiceBinding)
                .signingX509Credentials(c -> {
                    if (signingCredentialPrivateKeyLocation != null && signingCredentialCertificateLocation != null) {
                        c.add(getSigningCredential(signingCredentialPrivateKeyLocation, signingCredentialCertificateLocation));
                    }
                })
                .decryptionX509Credentials(c -> {
                    if (encryptionCredentialPrivateKeyLocation != null && encryptionCredentialCertificateLocation != null) {
                        c.add(getEncryptionCredential(encryptionCredentialPrivateKeyLocation, encryptionCredentialCertificateLocation));
                    }
                })
                .build();
        }
        catch (Exception e) {
            LOGGER.warn("Could not refresh RelyingPartyRegistration configuration.", e);
        }
    }

    @Override
    @SuppressWarnings("NullableProblems")
    public Iterator<RelyingPartyRegistration> iterator() {
        return Collections.singleton(relyingPartyRegistration).iterator();
    }
}
