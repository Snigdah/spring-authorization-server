package com.example.authserver.config;

import com.example.authserver.entity.UserEntity;
import com.example.authserver.repository.UserRepository;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.*;

@Configuration
public class TokenCustomizerConfig {

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
            UserRepository userRepository) {

        return context -> {

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    && context.getPrincipal().getPrincipal() instanceof UserDetails userDetails) {

                UserEntity user = userRepository
                        .findByUsername(userDetails.getUsername())
                        .orElseThrow();

                context.getClaims().claim("user_id", user.getId());
                context.getClaims().claim("username", user.getUsername());
                context.getClaims().claim("phone", user.getPhoneNumber());
                context.getClaims().claim("email", user.getEmail());
                context.getClaims().claim("org_id", user.getOrgId());

                context.getClaims().claim(
                        "roles",
                        userDetails.getAuthorities()
                                .stream()
                                .map(a -> a.getAuthority())
                                .toList()
                );
            }
        };
    }

}
