package net.engineerAnsh.journalApp.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.engineerAnsh.journalApp.Dto.admin.CreateAdminDto;
import net.engineerAnsh.journalApp.Dto.auth.AuthResponseDto;
import net.engineerAnsh.journalApp.Dto.user.*;
import net.engineerAnsh.journalApp.Entity.Journal;
import net.engineerAnsh.journalApp.Entity.User;
import net.engineerAnsh.journalApp.Repository.JournalRepository;
import net.engineerAnsh.journalApp.Repository.UserRepository;
import net.engineerAnsh.journalApp.Utils.JwtUtils;
import net.engineerAnsh.journalApp.enums.Role;
import net.engineerAnsh.journalApp.exception.exceptions.*;
import org.bson.types.ObjectId;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final JournalRepository journalRepository;
    private final PasswordEncoder passwordEncoder;
    private final CloudinaryService cloudinaryService;
    private final JwtUtils jwtUtils;
    private static final String USERNAME_CHANGED = "Username updated successfully.";

    private String getLoggedInUser() {
        Authentication userAuthenticated = SecurityContextHolder.getContext().getAuthentication(); // Again, 'SecurityContextHolder.getContext().getAuthentication() '-> gives the current logged-in user...
        return userAuthenticated.getName();
    }

    private UserProfileResponseDto mapToUserProfileResponse(User user) {
        return new UserProfileResponseDto(
                user.getId().toString(),
                user.getUsername(),
                user.getEmail(),
                user.getCity(),
                user.isSentimentAnalysis(),
                user.getRoles(),
                user.getProfileImageUrl(),
                user.getCreatedAt(),
                user.getUpdatedAt(),
                user.hasPassword(),
                user.hasGoogle()
        );
    }

    private AuthResponseDto mapToAuthResponse(String token) {
        return new AuthResponseDto(
                UserService.USERNAME_CHANGED,
                token,
                "Bearer"
        );
    }

    private void requirePasswordAuthentication(User user) {

        if (!user.hasPassword()) {
            throw new ForbiddenException(
                    "Password changes are not available for Google-only accounts."
            );
        }
    }

    public void saveUser(User user) {
        userRepository.save(user);
    }

    public List<UserProfileResponseDto> getAll() {
        return userRepository
                .findAll()
                .stream()
                .map(this::mapToUserProfileResponse)
                .toList();
    }

    public User findUserByUserName(String userName) {
        return userRepository.findByUsername(userName);
    }

    @Transactional
    public void saveAdmin(CreateAdminDto request) {
        User user = findUserByUserName(request.getUsername());
        if (user == null) throw new ResourceNotFoundException("User not Found");

        if (!user.getEmail().equals(request.getEmail())) {
            throw new BadRequestException("User email is wrong");
        }

        if (user.getRoles().contains(Role.ADMIN)) {
            throw new BadRequestException("User is already admin...");
        }

        user.getRoles().add(Role.ADMIN);
        userRepository.save(user);
    }

    public void changePassword(
            ChangePasswordRequestDto request
    ) {

        String userName = getLoggedInUser();

        User user =
                findUserByUserName(userName);

        if (user == null) {
            throw new ResourceNotFoundException(
                    "User not Found"
            );
        }

        /*
         * ----------------------------------------
         * Account authentication capability
         * ----------------------------------------
         *
         * Google-only accounts do not have a
         * password and therefore cannot change one.
         */
        requirePasswordAuthentication(user);

        /*
         * ----------------------------------------
         * Verify current password
         * ----------------------------------------
         */
        if (!passwordEncoder.matches(
                request.getCurrentPassword(),
                user.getPassword()
        )) {

            throw new BadRequestException(
                    "Current password is incorrect."
            );
        }

        /*
         * ----------------------------------------
         * Confirm new password
         * ----------------------------------------
         */
        if (!request.getNewPassword()
                .equals(request.getConfirmPassword())) {

            throw new BadRequestException(
                    "New password and confirm password do not match."
            );
        }

        /*
         * ----------------------------------------
         * Prevent reusing current password
         * ----------------------------------------
         */
        if (passwordEncoder.matches(
                request.getNewPassword(),
                user.getPassword()
        )) {

            throw new BadRequestException(
                    "New password cannot be the same as the current password."
            );
        }

        /*
         * ----------------------------------------
         * Save new password
         * ----------------------------------------
         */
        user.setPassword(
                passwordEncoder.encode(
                        request.getNewPassword()
                )
        );

        userRepository.save(user);
    }

    public void changeEmail(
            ChangeEmailRequestDto request
    ) {

        String userName = getLoggedInUser();

        User user =
                findUserByUserName(userName);

        if (user == null) {
            throw new ResourceNotFoundException(
                    "User not Found"
            );
        }

        /*
         * ----------------------------------------
         * Google-linked accounts
         * ----------------------------------------
         *
         * JournalFlow keeps the email immutable
         * once Google is linked.
         *
         * This covers:
         *
         * Google-only      → blocked
         * Local + Google   → blocked
         */
        if (user.hasGoogle()) {

            throw new ForbiddenException(
                    "Email changes are not available for Google-linked accounts."
            );
        }

        /*
         * ----------------------------------------
         * Local-only account
         * ----------------------------------------
         */
        requirePasswordAuthentication(user);

        /*
         * ----------------------------------------
         * Verify current password
         * ----------------------------------------
         */
        if (!passwordEncoder.matches(
                request.getPassword(),
                user.getPassword()
        )) {

            throw new BadRequestException(
                    "Password is incorrect."
            );
        }

        /*
         * ----------------------------------------
         * Check email availability
         * ----------------------------------------
         */
        if (userRepository.existsByEmail(
                request.getNewEmail()
        )) {

            throw new DuplicateResourceException(
                    "newEmail",
                    "Email already exists."
            );
        }

        /*
         * ----------------------------------------
         * Prevent same email
         * ----------------------------------------
         */
        if (user.getEmail()
                .equalsIgnoreCase(
                        request.getNewEmail()
                )) {

            throw new BadRequestException(
                    "New email cannot be the same as the current email."
            );
        }

        /*
         * ----------------------------------------
         * Save new email
         * ----------------------------------------
         */
        user.setEmail(
                request.getNewEmail()
        );

        userRepository.save(user);
    }

    public AuthResponseDto changeUsername(ChangeUsernameRequestDto request) {

        String userName = getLoggedInUser();
        User user = findUserByUserName(userName); // getting the user by its userName...

        if (user == null) throw new ResourceNotFoundException("User not Found");

        String newUsername = request.getUsername();

        // Prevent updating to the same username
        if (user.getUsername().equalsIgnoreCase(newUsername)) {
            throw new BadRequestException("New username cannot be the same as the current username.");
        }

        // Check username availability
        if (userRepository.existsByUsername(newUsername)) {
            throw new DuplicateResourceException(
                    "username",
                    "Username is already taken."
            );
        }

        user.setUsername(newUsername);
        userRepository.save(user);

        String token = jwtUtils.generateToken(user.getUsername());
        return mapToAuthResponse(token);

    }

    @Transactional
    public void deleteUser(
            DeleteAccountRequestDto request
    ) {

        String userName =
                getLoggedInUser();

        User user =
                findUserByUserName(userName);

        if (user == null) {
            throw new ResourceNotFoundException(
                    "User not Found"
            );
        }

        /*
         * ----------------------------------------
         * Google-only accounts
         * ----------------------------------------
         */
        requirePasswordAuthentication(user);

        /*
         * ----------------------------------------
         * Verify current password
         * ----------------------------------------
         */
        if (!passwordEncoder.matches(
                request.getPassword(),
                user.getPassword()
        )) {

            throw new BadRequestException(
                    "Password is incorrect."
            );
        }

        /*
         * ----------------------------------------
         * Delete user's journals
         * ----------------------------------------
         */
        List<ObjectId> journalEntriesIds =
                user.getJournals()
                        .stream()
                        .map(Journal::getId)
                        .toList();

        journalRepository.deleteAllById(
                journalEntriesIds
        );

        /*
         * ----------------------------------------
         * Delete user
         * ----------------------------------------
         */
        userRepository.deleteByUsername(
                userName
        );
    }

    @Transactional
    public void deleteGoogleOnlyAccount(
            String userId,
            String googleSubject
    ) {

        if (
                userId == null ||
                        userId.isBlank()
        ) {

            throw new UnauthorizedException(
                    "Delete-account identity is missing."
            );
        }

        if (
                googleSubject == null ||
                        googleSubject.isBlank()
        ) {

            throw new UnauthorizedException(
                    "Google identity is missing."
            );
        }

        ObjectId objectId;

        try {

            objectId =
                    new ObjectId(userId);

        } catch (IllegalArgumentException ex) {

            throw new UnauthorizedException(
                    "Delete-account identity is invalid."
            );
        }

        User user =
                userRepository
                        .findById(objectId)
                        .orElseThrow(() ->
                                new ResourceNotFoundException(
                                        "User not found."
                                )
                        );

        /*
         * ----------------------------------------
         * SECURITY RULE #1
         *
         * Only Google-only accounts can use
         * this deletion path.
         * ----------------------------------------
         */
        if (user.hasPassword()) {

            throw new ForbiddenException(
                    "This account must be deleted using its password."
            );
        }

        /*
         * ----------------------------------------
         * SECURITY RULE #2
         *
         * The account must actually be linked
         * with Google.
         * ----------------------------------------
         */
        if (!user.hasGoogle()) {

            throw new ForbiddenException(
                    "This account is not linked with Google."
            );
        }

        /*
         * ----------------------------------------
         * SECURITY RULE #3
         *
         * Google subject from the fresh OAuth
         * authentication must exactly match the
         * Google identity linked to this account.
         * ----------------------------------------
         */
        if (
                !user.getGoogleSubject()
                        .equals(googleSubject)
        ) {

            throw new UnauthorizedException(
                    "Google account does not match this user."
            );
        }

        /*
         * ----------------------------------------
         * Delete journals.
         * ----------------------------------------
         */
        List<ObjectId> journalEntriesIds =
                user.getJournals()
                        .stream()
                        .map(Journal::getId)
                        .toList();

        journalRepository.deleteAllById(
                journalEntriesIds
        );

        /*
         * ----------------------------------------
         * Delete user.
         * ----------------------------------------
         */
        userRepository.deleteById(
                objectId
        );
    }

    @Transactional
    public void updateUser(UpdateProfileRequestDto request) {
        String userName = getLoggedInUser();
        User savedUser = findUserByUserName(userName); // getting the user by its userName...

        if (savedUser == null) throw new ResourceNotFoundException("User not Found");

        if (request.getCity() != null && !request.getCity().isEmpty()) {
            savedUser.setCity(request.getCity());
        }

        if (request.isSentimentAnalysisEnabled() != savedUser.isSentimentAnalysis()) {
            savedUser.setSentimentAnalysis(request.isSentimentAnalysisEnabled());
        }

        userRepository.save(savedUser);
    }

    public UserProfileResponseDto getUser() {
        String username = getLoggedInUser();
        return mapToUserProfileResponse(findUserByUserName(username));
    }

    @Transactional
    public ProfileImageResponseDto uploadProfileImage(MultipartFile image) {

        // Get the currently authenticated user
        String username = getLoggedInUser();

        User user = findUserByUserName(username);

        if (user == null) {
            throw new ResourceNotFoundException("User not found.");
        }

        // Keep the old public id before replacing it
        String oldPublicId = user.getProfileImagePublicId();

        // Upload the new image
        ImageUploadResponse uploadResponse =
                cloudinaryService.uploadProfileImage(image);

        // Update user with the new image details
        user.setProfileImageUrl(uploadResponse.getImageUrl());
        user.setProfileImagePublicId(uploadResponse.getPublicId());

        // Save the updated user
        saveUser(user);

        // Delete the previous image after everything else succeeds
        if (oldPublicId != null && !oldPublicId.isBlank()) {
            try {
                cloudinaryService.deleteImage(oldPublicId);
            } catch (Exception ex) {
                // Log the exception.
                // We don't want the whole request to fail because
                // deleting the old image was unsuccessful.
                log.warn("Failed to delete old Cloudinary image: {}", oldPublicId, ex);
            }
        }

        return ProfileImageResponseDto.builder()
                .message("Profile image updated successfully.")
                .profileImageUrl(uploadResponse.getImageUrl())
                .build();
    }

}