package net.engineerAnsh.journalApp.Config.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import lombok.RequiredArgsConstructor;

import net.engineerAnsh.journalApp.Dto.auth.GoogleProvisioningResult;
import net.engineerAnsh.journalApp.Entity.User;
import net.engineerAnsh.journalApp.Service.GoogleUserProvisioningService;
import net.engineerAnsh.journalApp.Service.UserService;
import net.engineerAnsh.journalApp.Utils.JwtUtils;
import net.engineerAnsh.journalApp.enums.GoogleProvisioningStatus;
import net.engineerAnsh.journalApp.enums.OAuthFlow;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class GoogleOAuth2SuccessHandler
        implements AuthenticationSuccessHandler {

    private static final String OAUTH_TOKEN_COOKIE =  "JOURNALFLOW_OAUTH_TOKEN";
    private final GoogleUserProvisioningService googleUserProvisioningService;
    private final UserService userService;
    private final JwtUtils jwtUtils;

    @Value("${app.oauth2.frontend-success-url}")
    private String frontendSuccessUrl;

    @Value("${app.oauth2.frontend-signup-url}")
    private String frontendSignupUrl;

    @Value("${app.oauth2.frontend-login-url}")
    private String frontendLoginUrl;

    @Value("${app.oauth2.cookie.secure:false}")
    private boolean oauthCookieSecure;

    @Value("${app.oauth2.cookie.same-site:Lax}")
    private String oauthCookieSameSite;

    private void handleDeleteAccount(
            HttpServletRequest request,
            HttpServletResponse response,
            OidcUser oidcUser
    ) throws IOException, ServletException {

        HttpSession session =
                request.getSession(false);

        if (session == null) {
            throw new ServletException(
                    "Delete-account OAuth session is missing."
            );
        }

        /*
         * ----------------------------------------
         * Read target user ID
         * ----------------------------------------
         */
        Object targetUserIdValue =
                session.getAttribute(
                        OAuth2SessionConstants
                                .DELETE_ACCOUNT_USER_ID
                );

        /*
         * Remove immediately.
         *
         * This is one-time state.
         */
        session.removeAttribute(
                OAuth2SessionConstants
                        .DELETE_ACCOUNT_USER_ID
        );

        if (!(targetUserIdValue instanceof String targetUserId)
                || targetUserId.isBlank()) {

            throw new ServletException(
                    "Delete-account target is missing."
            );
        }

        /*
         * ----------------------------------------
         * Read authenticated Google subject
         * ----------------------------------------
         */
        String googleSubject =
                oidcUser.getSubject();

        if (
                googleSubject == null ||
                        googleSubject.isBlank()
        ) {

            throw new ServletException(
                    "Google account identifier is missing."
            );
        }

        /*
         * ----------------------------------------
         * Delete only after the service verifies:
         *
         * 1. target user exists
         * 2. target user is Google-only
         * 3. target user has Google linked
         * 4. target user's googleSubject matches
         *    the freshly authenticated Google subject
         * ----------------------------------------
         */
        userService
                .deleteGoogleOnlyAccount(
                        targetUserId,
                        googleSubject
                );

        /*
         * ----------------------------------------
         * Redirect to login.
         *
         * The frontend will clear its local JWT
         * in the next frontend-security phase.
         * ----------------------------------------
         */
        response.sendRedirect(
                frontendLoginUrl
                        + "?message=account_deleted"
        );
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        /*
         * ----------------------------------------
         * 1. Validate OAuth2 authentication
         * ----------------------------------------
         */
        if (
                !(authentication
                        instanceof OAuth2AuthenticationToken oauth2Token)
        ) {

            throw new ServletException(
                    "Unexpected OAuth2 authentication type."
            );
        }

        /*
         * ----------------------------------------
         * 2. Read Google OIDC identity
         * ----------------------------------------
         */
        if (
                !(oauth2Token.getPrincipal()
                        instanceof OidcUser oidcUser)
        ) {

            throw new ServletException(
                    "Google OIDC user information is missing."
            );
        }

        /*
         * ----------------------------------------
         * 3. Read LOGIN / SIGNUP
         * ----------------------------------------
         */
        OAuthFlow oauthFlow =
                getAndRemoveOAuthFlow(
                        request
                );

        if (oauthFlow == OAuthFlow.DELETE_ACCOUNT) {

            handleDeleteAccount(
                    request,
                    response,
                    oidcUser
            );

            return;
        }

        /*
         * ----------------------------------------
         * 4. Provisioning decision
         * ----------------------------------------
         */
        GoogleProvisioningResult result =
                googleUserProvisioningService
                        .findOrCreateUser(
                                oidcUser,
                                oauthFlow
                        );

        /*
         * ----------------------------------------
         * LOGIN + NO ACCOUNT
         * ----------------------------------------
         */
        if (
                result.getStatus() ==
                        GoogleProvisioningStatus
                                .SIGNUP_REQUIRED
        ) {

            redirectToSignup(
                    response
            );

            return;
        }

        /*
         * ----------------------------------------
         * SIGNUP + ACCOUNT EXISTS
         * ----------------------------------------
         */
        if (
                result.getStatus() ==
                        GoogleProvisioningStatus
                                .ACCOUNT_EXISTS
        ) {

            redirectToLogin(
                    response,
                    "account_exists"
            );

            return;
        }

        /*
         * ----------------------------------------
         * SIGNUP + NEW ACCOUNT
         * ----------------------------------------
         */
        if (
                result.getStatus() ==
                        GoogleProvisioningStatus
                                .ACCOUNT_CREATED
        ) {

            redirectToLogin(
                    response,
                    "google_account_created"
            );

            return;
        }

        /*
         * ----------------------------------------
         * AUTHENTICATE
         * ----------------------------------------
         *
         * Used for:
         *
         * LOGIN + existing Google
         *
         * LOGIN + existing LOCAL same email
         */
        User user =
                result.getUser();

        if (user == null) {

            throw new ServletException(
                    "JournalFlow user is missing."
            );
        }

        String jwt =
                jwtUtils.generateToken(
                        user.getUsername()
                );

        /*
         * ----------------------------------------
         * TEMPORARY OAUTH HANDOFF COOKIE
         * ----------------------------------------
         */
        ResponseCookie oauthCookie =
                ResponseCookie
                        .from(
                                OAUTH_TOKEN_COOKIE,
                                jwt
                        )
                        .httpOnly(true)
                        .secure(oauthCookieSecure)
                        .sameSite(oauthCookieSameSite)
                        .path("/")
                        .maxAge(60)
                        .build();

        response.addHeader(
                "Set-Cookie",
                oauthCookie.toString()
        );

        /*
         * ----------------------------------------
         * FRONTEND CALLBACK
         * ----------------------------------------
         */
        response.sendRedirect(
                frontendSuccessUrl
        );
    }

    private OAuthFlow getAndRemoveOAuthFlow(
            HttpServletRequest request
    ) throws ServletException {

        HttpSession session =
                request.getSession(false);

        if (session == null) {

            throw new ServletException(
                    "OAuth session is missing."
            );
        }

        Object flow =
                session.getAttribute(
                        OAuth2SessionConstants
                                .GOOGLE_OAUTH_FLOW
                );

        /*
         * Remove immediately because this is
         * one-time OAuth flow state.
         */
        session.removeAttribute(
                OAuth2SessionConstants
                        .GOOGLE_OAUTH_FLOW
        );

        if (
                !(flow instanceof OAuthFlow oauthFlow)
        ) {

            throw new ServletException(
                    "OAuth flow context is missing or invalid."
            );
        }

        return oauthFlow;
    }

    private void redirectToSignup(
            HttpServletResponse response
    ) throws IOException {

        response.sendRedirect(
                frontendSignupUrl
                        + "?error=account_not_found"
        );
    }

    private void redirectToLogin(
            HttpServletResponse response,
            String code
    ) throws IOException {

        response.sendRedirect(
                frontendLoginUrl
                        + "?message="
                        + code
        );
    }
}