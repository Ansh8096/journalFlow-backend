package net.engineerAnsh.journalApp.Entity;

import lombok.*;
import net.engineerAnsh.journalApp.enums.AuthProvider;
import net.engineerAnsh.journalApp.enums.Role;
import org.bson.types.ObjectId;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.util.List;

@Document(collection = "Users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    private ObjectId id;

    @Indexed(unique = true)
    @NonNull
    private String username;

    /**
     * Password is required for LOCAL accounts.
     * It is null for GOOGLE accounts.
     */
    private String password;

    @Indexed(unique = true)
    private String email;

    private boolean sentimentAnalysis;

    private String city;

    private List<Role> roles;

    /**
     * User's journal references.
     */
    @DBRef
    private List<Journal> journals;

    @CreatedDate
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    private String profileImageUrl;

    private String profileImagePublicId;

    /**
     * Authentication provider used by this account.
     *
     * LOCAL  -> username/password authentication
     * GOOGLE -> Google OAuth2/OIDC authentication
     */
    @Builder.Default
    private AuthProvider authProvider =
            AuthProvider.LOCAL;

    /**
     * Google's stable OIDC subject identifier.
     *
     * Null for LOCAL accounts.
     * Populated for GOOGLE accounts.
     */
    @Indexed(unique = true, sparse = true)
    private String googleSubject;

    public boolean hasPassword() {
        return password != null
                && !password.isBlank();
    }

    public boolean hasGoogle() {
        return googleSubject != null
                && !googleSubject.isBlank();
    }
}