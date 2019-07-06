INSERT IGNORE INTO roles(name) VALUES('ROLE_USER');
INSERT IGNORE INTO roles(name) VALUES('ROLE_ADMIN') ;

INSERT IGNORE INTO users(created_at, updated_at, email, name, password, username)
    VALUES (NOW(), NOW(), 'test@user.com', 'admin', 'password', 'admin');