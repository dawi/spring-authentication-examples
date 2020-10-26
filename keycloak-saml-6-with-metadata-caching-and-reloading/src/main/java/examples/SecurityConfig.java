package examples;

import examples.repository.CachingReloadingSingleRelyingPartyRegistrationRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Optional;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${relying-party-registration.registration-id}")
    private String registrationId;

    @Value("${relying-party-registration.relying-party-entity-id}")
    private String relyingPartyEntityId;

    @Value("${relying-party-registration.metadata-url}")
    private String metadataUrl;

    @Value("${relying-party-registration.assertion-consumer-service-binding}")
    private Saml2MessageBinding assertionConsumerServiceBinding;

    @Value("${relying-party-registration.identityprovider.metadata-uri}")
    private String identityproviderMetadataUri;

    @Value("${relying-party-registration.identityprovider.metadata-cache-file}")
    private String identityproviderMetadataCacheFile;

    @Value("${relying-party-registration.signing.private-key-location:}")
    private Optional<Resource> signingCredentialPrivateKeyLocation;

    @Value("${relying-party-registration.signing.certificate-location:}")
    private Optional<Resource> signingCredentialCertificateLocation;

    @Value("${relying-party-registration.encryption.private-key-location:}")
    private Optional<Resource> encryptionCredentialPrivateKeyLocation;

    @Value("${relying-party-registration.encryption.certificate-location:}")
    private Optional<Resource> encryptionCredentialCertificateLocation;

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {

        return new CachingReloadingSingleRelyingPartyRegistrationRepository(
            registrationId,
            identityproviderMetadataUri,
            identityproviderMetadataCacheFile,
            relyingPartyEntityId,
            assertionConsumerServiceBinding,
            signingCredentialPrivateKeyLocation.orElse(null),
            signingCredentialCertificateLocation.orElse(null),
            encryptionCredentialPrivateKeyLocation.orElse(null),
            encryptionCredentialCertificateLocation.orElse(null)
        );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        configureSaml2MetadataFilter(http);

        http.authorizeRequests()
            .antMatchers("/login.html").permitAll()
            .anyRequest().authenticated();

        http.saml2Login()
            .loginPage("/login.html");
    }

    private void configureSaml2MetadataFilter(HttpSecurity httpSecurity) {

        final Saml2MetadataFilter saml2MetadataFilter = new Saml2MetadataFilter(
            new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository()),
            new OpenSamlMetadataResolver()
        );

        saml2MetadataFilter.setRequestMatcher(new AntPathRequestMatcher(metadataUrl, "GET"));

        httpSecurity.addFilterBefore(saml2MetadataFilter, Saml2WebSsoAuthenticationFilter.class);
    }
}
