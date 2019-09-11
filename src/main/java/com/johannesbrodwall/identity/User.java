package com.johannesbrodwall.identity;

import java.util.UUID;

public class User {
    private final String username;
    private final UserRole role;
    private UUID id = UUID.randomUUID();

    public User(String username, UserRole role) {
        this.username = username;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public UserRole getRole() {
        return role;
    }

    public UUID getId() {
        return id;
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", role=" + role +
                ", id=" + id +
                '}';
    }
}
