package org.sid.customerservice;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class CustomerRestAPI {
    @GetMapping("/customers")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String,Object> customer(Authentication authentication){
        return Map.of("name","Mohamed","email", "med@gmail.com",
                "username",authentication.getName(),
                "scope",authentication.getAuthorities());
    }
}
