package com.johannesbrodwall.identity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserRepository {
    private static Map<String, UserRole> userRolesMap = new HashMap<>(Map.of(
            "24079420405", new UserRole("admin"),
            "24079418990", new UserRole(null)
    ));

    public UserRole getRoles(String pid) {
        if (!userRolesMap.containsKey(pid)) {
            userRolesMap.put(pid, null);
        }
        return userRolesMap.get(pid);
    }

    public List<User> fetchUserRoles() {
        ArrayList<User> result = new ArrayList<>();
        userRolesMap.forEach((k,v) -> result.add(new User(k, v)));
        return result;
    }
}
