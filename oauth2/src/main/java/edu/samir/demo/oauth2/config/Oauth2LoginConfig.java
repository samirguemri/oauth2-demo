package edu.samir.demo.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class Oauth2LoginConfig extends WebSecurityConfigurerAdapter {

    private final Environment environment;
    private static List<String> clientRegistrationsId = Arrays.asList("github", "google", "facebook");
    private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

    @Autowired
    public Oauth2LoginConfig(final Environment environment) {
        this.environment = environment;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/oauth_login").permitAll()
                .mvcMatchers("/api/**").authenticated()
                .anyRequest().permitAll();
        http.oauth2Login()
                .loginPage("/oauth_login")
                .defaultSuccessUrl("/loginSuccess")
                .failureUrl("/loginFailure")
            .and()
            .logout().logoutSuccessUrl("/").permitAll();
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(this.clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = this.clientRegistrationsId.stream()
                .map(registrationId -> this.getRegistration(registrationId))
                .filter(registration -> registration != null)
                .collect(Collectors.toList());
        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration(String registrationId) {

        String clientId = environment.getProperty(CLIENT_PROPERTY_KEY + registrationId + ".client-id");

        if (clientId == null) {
            return null;
        }

        String clientSecret = environment.getProperty(CLIENT_PROPERTY_KEY + registrationId + ".client-secret");

        switch (registrationId) {
            case "github" -> {
                return CommonOAuth2Provider.GITHUB.getBuilder(registrationId)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .build();
            }
            case "google" -> {
                return CommonOAuth2Provider.GOOGLE.getBuilder(registrationId)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .build();
            }case "facebook" -> {
                return CommonOAuth2Provider.FACEBOOK.getBuilder(registrationId)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .build();
            }
            default -> {
                return null;
            }
        }
    }
}
