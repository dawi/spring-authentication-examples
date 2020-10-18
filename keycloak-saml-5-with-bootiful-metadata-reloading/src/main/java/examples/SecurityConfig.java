package examples;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${additional-saml-configuration.metadata-url}")
    private String metadataUrl;

    @Autowired
    private AutoReloadingRelyingPartyRegistrationRepository autoReloadingRelyingPartyRegistrationRepository;

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        final Saml2MetadataFilter saml2MetadataFilter = new Saml2MetadataFilter(
            new DefaultRelyingPartyRegistrationResolver(autoReloadingRelyingPartyRegistrationRepository),
            new OpenSamlMetadataResolver()
        );

        saml2MetadataFilter.setRequestMatcher(new AntPathRequestMatcher(metadataUrl, "GET"));

        httpSecurity
            .addFilterBefore(saml2MetadataFilter, Saml2WebSsoAuthenticationFilter.class)
            .authorizeRequests(auth -> auth.anyRequest().authenticated())
            .saml2Login();
    }
}
