package com.go2it.edu.emplyeenanagementsystem.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * @author Alex Ryzhkov
 */
@Configuration
@EnableJpaAuditing
public class AuditConfig {
	// That's all here for now. We'll add more auditing configurations later.
}
