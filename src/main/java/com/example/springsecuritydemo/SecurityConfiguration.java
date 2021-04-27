package com.example.springsecuritydemo;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("Alpha").
                password("beta").
                roles("USER")
                .and()
                .withUser("hii")
                .password("bye")
                .roles("ADMIN");
    }

    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()

                .antMatchers("/admin").hasRole("ADMIN")  //this tells that admin url is accessible by the person who has ADMIN role
                .antMatchers("/user").hasAnyRole("USER" , "ADMIN")    //this tells that user url is accessible by the person who has USER role
                .antMatchers("/").permitAll()             //this tells that root url is accessible to all roles
                .and()
                .formLogin();
    }
}
