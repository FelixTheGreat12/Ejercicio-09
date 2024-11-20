package com.upiiz.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity

public class SecurityConfig {
    // Security FILTER  CHAIN - Cadena de filtros de seguridad
    // Bean - Singleton - Tener una sola instancia
    @Autowired
    AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        // Configurar los filtros personalizados
        return httpSecurity.httpBasic(Customizer.withDefaults()).sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {
                    http.requestMatchers(HttpMethod.GET,"/api/v2/listar").hasAuthority("READ");
                    http.requestMatchers(HttpMethod.GET, "/api/v2/actualizar").hasAuthority("UPDATE");
                    http.requestMatchers(HttpMethod.GET, "/api/v2/eliminar").hasAuthority("DELETE");
                    http.requestMatchers(HttpMethod.GET, "/api/v2/crear").hasAuthority("CREATE");
                })
                .build();
    }
    // Authentication Manager - Lo vamos a obtener de una instancia que ya existe
    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }

    // Authentication Provider - DAO
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return daoAuthenticationProvider;
    }
    // Password Encoder
    @Bean
    public PasswordEncoder passwordEncoder(){
        //return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }
    // UserDataallServices - Base de datos o usuarios en memoria
    @Bean
    public UserDetailsService userDetailsService(){
        // Definir usuarrios en memoria
        // No vamos a obtenerlo de una base de datos:
        UserDetails usuario1 = User.withUsername("Miguel").password("miguel1234").roles("ADMIN").authorities("READ","CREATE","UPDATE","DELETE").build();
        UserDetails usuario2 = User.withUsername("Rodrigo").password("rodrigo1234").roles("USER").authorities("READ","UPDATE").build();
        UserDetails usuarioInvitado = User.withUsername("Guest").password("guest").roles("GUEST").build();

        List<UserDetails> userDetailsList = new ArrayList<UserDetails>();
        userDetailsList.add(usuario1);
        userDetailsList.add(usuario2);
        userDetailsList.add(usuarioInvitado);
        return new InMemoryUserDetailsManager();
    }
}
