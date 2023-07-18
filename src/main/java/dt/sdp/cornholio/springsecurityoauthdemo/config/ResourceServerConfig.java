package dt.sdp.cornholio.springsecurityoauthdemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class ResourceServerConfig {
//    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
//    String jwkSetUri;

    @Bean
//    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         @formatter:off
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .antMatchers("/oauth2/**").permitAll()
                        .antMatchers(HttpMethod.GET, "/articles/**").hasAuthority("SCOPE_articles:read")
                        .antMatchers(HttpMethod.POST, "/articles/**").hasAuthority("SCOPE_articles:write")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//         @formatter:on
        return http.build();
    }

//    @Bean
//    public JwtDecoder jwtDecoder() {
//        return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
//    }
}
