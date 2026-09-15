package net.engineerAnsh.journalApp.Controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import net.engineerAnsh.journalApp.Dto.auth.AuthResponseDto;
import net.engineerAnsh.journalApp.Dto.common.MessageResponseDto;
import net.engineerAnsh.journalApp.Dto.user.*;
import net.engineerAnsh.journalApp.Service.UserService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController // @RestController: Marks this as a REST controller — meaning it will handle HTTP requests and automatically convert Java objects to JSON in responses...
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
@Tag(name = "User APIs", description = "Read, Update & Delete User")
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    @Operation(summary = "Get the user")
    public ResponseEntity<UserProfileResponseDto> getUser() {
        UserProfileResponseDto user = userService.getUser();
        return ResponseEntity.ok(user);
    }

    @PatchMapping("/me")
    @Operation(summary = "Update the current user")
    public ResponseEntity<MessageResponseDto> updateUser(
            @RequestBody @Valid UpdateProfileRequestDto request
    ) {
        userService.updateUser(request);
        return ResponseEntity.ok(
                MessageResponseDto.builder()
                        .message("User updated successfully.").build()
        );
    }

    @PatchMapping("/me/password")
    public ResponseEntity<MessageResponseDto> changePassword(
            @Valid @RequestBody ChangePasswordRequestDto request
    ){
        userService.changePassword(request);

        return ResponseEntity.ok(
                MessageResponseDto.builder()
                        .message("Password updated successfully.").build()
        );
    }

    @PatchMapping("/me/email")
    public ResponseEntity<MessageResponseDto> changeEmail(
            @Valid @RequestBody ChangeEmailRequestDto request
    ){
        userService.changeEmail(request);
        return ResponseEntity.ok(
                MessageResponseDto.builder()
                        .message("Email updated successfully.").build()
        );
    }

    @PatchMapping("/me/username")
    public ResponseEntity<AuthResponseDto> changeUsername(
            @Valid @RequestBody ChangeUsernameRequestDto request
    ){
        return ResponseEntity.ok(userService.changeUsername(request));
    }

    @DeleteMapping("/me")
    @Operation(summary = "Delete the user")
    public ResponseEntity<MessageResponseDto> deleteTheUser(
            @Valid @RequestBody DeleteAccountRequestDto request
    ) {
        userService.deleteUser(request);
        return ResponseEntity.ok(
                MessageResponseDto.builder()
                        .message("User deleted successfully.").build()
        );    }

    @PatchMapping(
            value = "me/profile-image",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE
    )
    @Operation(summary = "Upload or replace the user's profile image")
    public ResponseEntity<ProfileImageResponseDto> uploadProfileImage(
            @RequestParam("image") MultipartFile image
    ) {

        return ResponseEntity.ok(
                userService.uploadProfileImage(image)
        );

    }
}