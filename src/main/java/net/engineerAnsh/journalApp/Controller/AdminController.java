package net.engineerAnsh.journalApp.Controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import net.engineerAnsh.journalApp.Dto.admin.CreateAdminDto;
import net.engineerAnsh.journalApp.Dto.common.MessageResponseDto;
import net.engineerAnsh.journalApp.Dto.user.UserProfileResponseDto;
import net.engineerAnsh.journalApp.Service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
@Tag(name = "Admin APIs" , description = "Get-All-Users, Create-Admin & Run-App-Cache")
public class AdminController {


    private final UserService userService;

    @GetMapping("/all-users")
    @Operation(summary = "See all the existing users")
    public ResponseEntity<List<UserProfileResponseDto>> getAllUsers(){
        List<UserProfileResponseDto> allUsers = userService.getAll();
        return ResponseEntity.ok(allUsers);

    }

    @PostMapping ("/create-admin")
    @Operation(summary = "Create a new admin")
    public ResponseEntity<MessageResponseDto> createAdmins(@RequestBody @Valid CreateAdminDto request){
        userService.saveAdmin(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(MessageResponseDto.builder()
                        .message("Admin created successfully.")
                        .build()
                );
    }

}
