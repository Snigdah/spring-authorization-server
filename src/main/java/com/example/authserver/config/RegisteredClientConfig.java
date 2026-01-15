package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

@Configuration
public class RegisteredClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        // --- Public SPA Client ---
        RegisteredClient reactClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("react-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // public client
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oidcdebugger.com/debug")
                .scope("openid")
                .scope("api.read")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)          // enable PKCE
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        // --- Confidential Resource Server 1 ---
        RegisteredClient service1 = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("service1")
                .clientSecret("{noop}service1-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("service1.read")
                .scope("service1.write")
                .build();

        // --- Confidential Resource Server 2 ---
        RegisteredClient service2 = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("service2")
                .clientSecret("{noop}service2-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("service2.read")
                .scope("service2.write")
                .build();

        return new InMemoryRegisteredClientRepository(reactClient, service1, service2);
    }
}
