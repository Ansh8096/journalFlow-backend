package net.engineerAnsh.journalApp.Config.security;

import jakarta.servlet.http.HttpServletRequest;

import jakarta.servlet.http.HttpSession;

import net.engineerAnsh.journalApp.enums.OAuthFlow;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;

import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class GoogleAuthorizationRequestResolver
        implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver delegate;

    public GoogleAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository
    ) {

        this.delegate =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization"
                );
    }

    @Override
    public OAuth2AuthorizationRequest resolve(
            HttpServletRequest request
    ) {

        OAuth2AuthorizationRequest authorizationRequest =
                delegate.resolve(request);

        return customize(
                request,
                authorizationRequest
        );
    }

    @Override
    public OAuth2AuthorizationRequest resolve(
            HttpServletRequest request,
            String clientRegistrationId
    ) {

        OAuth2AuthorizationRequest authorizationRequest =
                delegate.resolve(
                        request,
                        clientRegistrationId
                );

        return customize(
                request,
                authorizationRequest
        );
    }

    private OAuth2AuthorizationRequest customize(
            HttpServletRequest request,
            OAuth2AuthorizationRequest authorizationRequest
    ) {

        if (authorizationRequest == null) {
            return null;
        }

        HttpSession session =
                request.getSession(false);

        if (session == null) {
            return authorizationRequest;
        }

        Object flow =
                session.getAttribute(
                        OAuth2SessionConstants
                                .GOOGLE_OAUTH_FLOW
                );

        if (flow != OAuthFlow.DELETE_ACCOUNT) {
            return authorizationRequest;
        }

        /*
         * ----------------------------------------
         * Force Google to authenticate again.
         * ----------------------------------------
         */
        return OAuth2AuthorizationRequest
                .from(
                        authorizationRequest
                )
                .additionalParameters(
                        parameters ->
                                parameters.put(
                                        "prompt",
                                        "login"
                                )
                )
                .build();
    }
}