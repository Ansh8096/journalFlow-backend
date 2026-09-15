package net.engineerAnsh.journalApp.Controller;

import jakarta.servlet.http.HttpSession;

import lombok.RequiredArgsConstructor;

import net.engineerAnsh.journalApp.Config.security.OAuth2SessionConstants;
import net.engineerAnsh.journalApp.Entity.User;
import net.engineerAnsh.journalApp.Service.UserService;
import net.engineerAnsh.journalApp.enums.OAuthFlow;
import net.engineerAnsh.journalApp.exception.exceptions.ForbiddenException;
import net.engineerAnsh.journalApp.exception.exceptions.ResourceNotFoundException;

import net.engineerAnsh.journalApp.exception.exceptions.UnauthorizedException;
import org.bson.types.ObjectId;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth/oauth2/google")
@RequiredArgsConstructor
public class GoogleOAuth2Controller {

    private final UserService userService;

    /**
     * Starts Google OAuth from the LOGIN page.
     */
    @GetMapping("/login")
    public ResponseEntity<Void> login(
            HttpSession session
    ) {

        session.setAttribute(
                OAuth2SessionConstants.GOOGLE_OAUTH_FLOW,
                OAuthFlow.LOGIN
        );

        return ResponseEntity
                .status(HttpStatus.FOUND)
                .location(
                        URI.create(
                                "/oauth2/authorization/google"
                        )
                )
                .build();
    }

    /**
     * Starts Google OAuth from the SIGNUP page.
     */
    @GetMapping("/signup")
    public ResponseEntity<Void> signup(
            HttpSession session
    ) {

        session.setAttribute(
                OAuth2SessionConstants.GOOGLE_OAUTH_FLOW,
                OAuthFlow.SIGNUP
        );

        return ResponseEntity
                .status(HttpStatus.FOUND)
                .location(
                        URI.create(
                                "/oauth2/authorization/google"
                        )
                )
                .build();
    }

    /**
     * Starts fresh Google authentication for
     * deleting a Google-only JournalFlow account.
     */
    @PostMapping("/delete-account/start")
    public ResponseEntity<Map<String, String>> startDeleteAccount(
            HttpSession session
    ) {

        Authentication authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();

        if (
                authentication == null ||
                        !authentication.isAuthenticated() ||
                        "anonymousUser".equals(
                                authentication.getName()
                        )
        ) {
            throw new UnauthorizedException(
                    "You must be logged in to delete your account."
            );
        }

        String username =
                authentication.getName();

        User user =
                userService.findUserByUserName(
                        username
                );

        if (user == null) {
            throw new ResourceNotFoundException(
                    "User not found."
            );
        }

        /*
         * ----------------------------------------
         * Only Google-only accounts use this flow.
         * ----------------------------------------
         */
        if (user.hasPassword()) {
            throw new ForbiddenException(
                    "This account must be deleted using your password."
            );
        }

        if (!user.hasGoogle()) {
            throw new ForbiddenException(
                    "This account is not linked with Google."
            );
        }

        if (user.getId() == null) {
            throw new IllegalStateException(
                    "User identifier is missing."
            );
        }

        /*
         * ----------------------------------------
         * Preserve DELETE_ACCOUNT flow.
         * ----------------------------------------
         */
        session.setAttribute(
                OAuth2SessionConstants.GOOGLE_OAUTH_FLOW,
                OAuthFlow.DELETE_ACCOUNT
        );

        /*
         * ----------------------------------------
         * Bind OAuth to this exact JournalFlow user.
         * ----------------------------------------
         */
        session.setAttribute(
                OAuth2SessionConstants.DELETE_ACCOUNT_USER_ID,
                user.getId().toHexString()
        );

        /*
         * ----------------------------------------
         * Frontend will navigate to this URL after
         * the authenticated request succeeds.
         * ----------------------------------------
         */
        Map<String, String> response =
                Map.of(
                        "authorizationUrl",
                        "/oauth2/authorization/google"
                );

        return ResponseEntity.ok(response);
    }
}