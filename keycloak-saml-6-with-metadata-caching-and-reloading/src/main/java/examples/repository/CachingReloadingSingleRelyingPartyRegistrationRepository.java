package examples.repository;

import examples.spring_5_5_0.RelyingPartyRegistrations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import static examples.repository.CertificateUtils.getEncryptionCredential;
import static examples.repository.CertificateUtils.getSigningCredential;

public class CachingReloadingSingleRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    private static final Logger LOGGER = LoggerFactory.getLogger(CachingReloadingSingleRelyingPartyRegistrationRepository.class);
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    private final String registrationId;
    private final String identityProviderMetadataUri;
    private final String identityProviderMetadataCacheFile;
    private final String relyingPartyEntityId;
    private final Saml2MessageBinding assertionConsumerServiceBinding;
    private final Resource signingCredentialPrivateKeyLocation;
    private final Resource signingCredentialCertificateLocation;
    private final Resource encryptionCredentialPrivateKeyLocation;
    private final Resource encryptionCredentialCertificateLocation;

    private RelyingPartyRegistration relyingPartyRegistration;

    public CachingReloadingSingleRelyingPartyRegistrationRepository(
        String registrationId,
        String identityProviderMetadataUri,
        String identityProviderMetadataCacheFile,
        String relyingPartyEntityId,
        Saml2MessageBinding assertionConsumerServiceBinding,
        Resource signingCredentialPrivateKeyLocation,
        Resource signingCredentialCertificateLocation,
        Resource encryptionCredentialPrivateKeyLocation,
        Resource encryptionCredentialCertificateLocation
    ) {

        this.registrationId = registrationId;

        this.identityProviderMetadataUri = identityProviderMetadataUri;
        this.identityProviderMetadataCacheFile = identityProviderMetadataCacheFile;

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
        downloadMetadata();
        buildRelyingPartyRegistration();
    }

    private void downloadMetadata() {

        LOGGER.debug("Download metadata from '{}'", identityProviderMetadataUri);

        final HttpResponse<byte[]> response;
        try {
            response = CLIENT.send(
                HttpRequest.newBuilder().uri(new URI(identityProviderMetadataUri)).GET().build(),
                BodyHandlers.ofByteArray()
            );
        }
        catch (Exception e) {
            LOGGER.warn("Could not download metadata from '" + identityProviderMetadataUri + "'", e);
            return;
        }

        if (response.statusCode() != 200) {
            LOGGER.warn("Could not download metadata from '{}'", identityProviderMetadataUri);
            return;
        }

        LOGGER.debug("Store metadata in '{}'", identityProviderMetadataCacheFile);

        try {
            Files.createDirectories(Paths.get(identityProviderMetadataCacheFile).getParent());
            Files.copy(new ByteArrayInputStream(response.body()), Paths.get(identityProviderMetadataCacheFile), StandardCopyOption.REPLACE_EXISTING);
        }
        catch (Exception e) {
            LOGGER.warn("Could not store metadata in '" + identityProviderMetadataCacheFile + "'", e);
        }
    }

    private void buildRelyingPartyRegistration() {
        try {
            this.relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation("file:" + identityProviderMetadataCacheFile)
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
}
