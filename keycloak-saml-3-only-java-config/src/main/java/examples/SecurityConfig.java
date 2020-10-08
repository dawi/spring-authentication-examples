package examples;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;

import static examples.CertUtil.getEncryptionCredential;
import static examples.CertUtil.getSigningCredential;
import static examples.CertUtil.getVerificationCredential;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Saml2X509Credential SIGNING_CREDENTIAL = getSigningCredential("credentials/signing.key", "credentials/signing.crt");
    private static final Saml2X509Credential DECRYPTION_CREDENTIAL = getEncryptionCredential("credentials/encryption.key", "credentials/encryption.crt");
    private static final Saml2X509Credential VERIFICATION_CREDENTIAL = getVerificationCredential("credentials/realm.crt");

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {

        final RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration
            .withRegistrationId("demo-saml-client")
            .entityId("demo-saml-client")
            .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
            .signingX509Credentials(c -> c.add(SIGNING_CREDENTIAL))
            .decryptionX509Credentials(c -> c.add(DECRYPTION_CREDENTIAL))
            .assertingPartyDetails(
                details -> details
                    .entityId("http://localhost:8081/auth/realms/DemoRealm")
                    .singleSignOnServiceBinding(Saml2MessageBinding.POST)
                    .singleSignOnServiceLocation("http://localhost:8081/auth/realms/DemoRealm/protocol/saml")
                    .verificationX509Credentials(c -> c.add(VERIFICATION_CREDENTIAL))
                    .wantAuthnRequestsSigned(true)
            )
            .build();

        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.addFilterBefore(
            new Saml2MetadataFilter(
                new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository()),
                new OpenSamlMetadataResolver()
            ),
            Saml2WebSsoAuthenticationFilter.class
        );

        httpSecurity
            .authorizeRequests(auth -> auth.anyRequest().authenticated())
            .saml2Login();
    }
}
