package net.engineerAnsh.journalApp.Dto.user;

import lombok.*;
import net.engineerAnsh.journalApp.enums.Role;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserProfileResponseDto {

    private String id;

    private String username;

    private String email;

    private String city;

    private boolean sentimentAnalysisEnabled;

    private List<Role> roles;

    private String profileImageUrl;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    private boolean hasPassword;

    private boolean hasGoogle;
}
