package com.example.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	auth.inMemoryAuthentication().withUser("sadab").password("{noop}sadab").authorities("ADMIN");
	auth.inMemoryAuthentication().withUser("annu").password("{noop}annu").authorities("EMPLOYEE");
	auth.inMemoryAuthentication().withUser("jay").password("{noop}jay").authorities("STUDENT");
	auth.inMemoryAuthentication().withUser("raju").password("{noop}raju").authorities("EMPLOYEE");
		
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/home").permitAll()
		.antMatchers("/welcome").authenticated()
		.antMatchers("/admin").hasAnyAuthority("ADMIN")
		.antMatchers("/emp").hasAnyAuthority("EMPLOYEE")
		.antMatchers("/std").hasAnyAuthority("STUDENT")
		
		//LoginFormDetails
		.and()
		.formLogin()
		.defaultSuccessUrl("/welcome", true)
		
		//LogoutFormDetails
		.and()
		.logout()
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		
		.and()
		.exceptionHandling()
		.accessDeniedPage("/denied");
		
	}
	


	

}
