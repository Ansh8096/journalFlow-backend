package net.engineerAnsh.journalApp.Config.security;

import lombok.RequiredArgsConstructor;
import net.engineerAnsh.journalApp.Filter.JwtFilter;
import net.engineerAnsh.journalApp.Service.UserDetailsServiceImpl;
import net.engineerAnsh.journalApp.enums.Role;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;
    private final GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler;
    private final GoogleOAuth2FailureHandler googleOAuth2FailureHandler;
    private final UserDetailsServiceImpl userDetails;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Value("${app.cors.allowed-origin}")
    private String allowedOrigin;

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {

        return http

                /*
                 * ----------------------------------------
                 * CORS
                 * ----------------------------------------
                 */
                .cors(
                        Customizer.withDefaults()
                )

                /*
                 * ----------------------------------------
                 * CSRF
                 * ----------------------------------------
                 *
                 * Your current authentication API is JWT-based,
                 * so we continue with your existing configuration
                 * for this phase.
                 */
                .csrf(
                        AbstractHttpConfigurer::disable
                )

                /*
                 * ----------------------------------------
                 * AUTHORIZATION
                 * ----------------------------------------
                 */
                .authorizeHttpRequests(
                        request -> request

                                /*
                                 * --------------------------------
                                 * Existing public authentication
                                 * endpoints
                                 * --------------------------------
                                 */
                                .requestMatchers(
                                        "/api/v1/auth/**",
                                        "/api/v1/public/**"
                                )
                                .permitAll()

                                /*
                                 * --------------------------------
                                 * OAuth2 login endpoints
                                 * --------------------------------
                                 *
                                 * These must be reachable before
                                 * the user has authenticated.
                                 */
                                .requestMatchers(
                                        "/oauth2/**",
                                        "/login/oauth2/**"
                                )
                                .permitAll()

                                /*
                                 * --------------------------------
                                 * Existing protected APIs
                                 * --------------------------------
                                 */
                                .requestMatchers(
                                        "/api/v1/journals/**",
                                        "/api/v1/users/**",
                                        "/api/v1/weather/**"
                                )
                                .authenticated()

                                /*
                                 * --------------------------------
                                 * Admin APIs
                                 * --------------------------------
                                 */
                                .requestMatchers(
                                        "/api/v1/admin/**"
                                )
                                .hasRole(
                                        Role.ADMIN.name()
                                )

                                /*
                                 * --------------------------------
                                 * Everything else
                                 * --------------------------------
                                 */
                                .anyRequest()
                                .permitAll()
                )

                /*
                 * ----------------------------------------
                 * GOOGLE OAUTH2 LOGIN
                 * ----------------------------------------
                 */
                .oauth2Login(
                        oauth -> oauth
                                .authorizationEndpoint(
                                        endpoint ->
                                                endpoint
                                                        .authorizationRequestResolver(
                                                                googleAuthorizationRequestResolver()
                                                        )
                                )
                                .successHandler(
                                        googleOAuth2SuccessHandler
                                )
                                .failureHandler(
                                        googleOAuth2FailureHandler
                                )
                )

                /*
                 * ----------------------------------------
                 * EXISTING JWT AUTHENTICATION
                 * ----------------------------------------
                 *
                 * IMPORTANT:
                 * We keep your existing JWT filter.
                 */
                .addFilterBefore(
                        jwtFilter,
                        UsernamePasswordAuthenticationFilter.class
                )

                .build();
    }

    /*
     * ----------------------------------------
     * PASSWORD AUTHENTICATION
     * ----------------------------------------
     */
    @Bean
    public DaoAuthenticationProvider configureGlobal(
            AuthenticationManagerBuilder auth,
            PasswordEncoder passwordEncoder
    ) throws Exception {

        DaoAuthenticationProvider authProvider =
                new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(
                userDetails
        );

        authProvider.setPasswordEncoder(
                passwordEncoder
        );

        return authProvider;
    }

    /*
     * ----------------------------------------
     * AUTHENTICATION MANAGER
     * ----------------------------------------
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration auth
    ) throws Exception {

        return auth.getAuthenticationManager();
    }

    /*
     * ----------------------------------------
     * CORS
     * ----------------------------------------
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration =
                new CorsConfiguration();

        configuration.setAllowedOrigins(
                List.of(allowedOrigin)
        );

        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE",
                        "PATCH",
                        "OPTIONS"
                )
        );

        configuration.setAllowedHeaders(
                List.of("*")
        );

        configuration.setAllowCredentials(
                true
        );

        configuration.setExposedHeaders(
                List.of(
                        HttpHeaders.CONTENT_DISPOSITION
                )
        );

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration(
                "/**",
                configuration
        );

        return source;
    }

    @Bean
    public OAuth2AuthorizationRequestResolver
    googleAuthorizationRequestResolver() {

        return new GoogleAuthorizationRequestResolver(
                clientRegistrationRepository
        );
    }
}