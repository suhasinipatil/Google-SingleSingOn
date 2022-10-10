package com.example.google;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class SecurityConfig  {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.csrf().disable().antMatcher("/**").authorizeRequests()
                .antMatchers("/", "/index").authenticated()
                .anyRequest().authenticated()
                .and()
                .oauth2Login().permitAll(true)
                .and()
                .logout()
                .invalidateHttpSession(true)
               .clearAuthentication(true)
                .logoutSuccessUrl("/");
        return httpSecurity.build();
    }
}
