package com.koendebruijn.template.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

import static javax.persistence.FetchType.EAGER;
import static javax.persistence.GenerationType.AUTO;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Builder
@AllArgsConstructor
@Table(name = "app_user")
public class User {
    @Id @GeneratedValue(strategy = AUTO)
    private Long id;
    private String name;
    private String username;
    @JsonIgnore
    private String password;

    @JsonIgnore
    private String accessToken;

    @JsonIgnore
    private String refreshToken;


    @ManyToMany(fetch = EAGER)
    private Collection<Role> roles = new ArrayList<>();

}
