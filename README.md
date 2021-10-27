# Spring REST API with JWT & Postgresql

## Clone this repo
```shell
git clone git@github.com:koendebruijn/spring-rest-jwt-template.git
```

## Edit properties
```properties
spring.datasource.url=DB_URL
spring.datasource.username=DB_USERNAME
spring.datasource.password=DB_PASSWORD
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect

# Do not use in production!
spring.jpa.properties.hibernate.format_sql=true
spring.jpa.hibernate.ddl-auto=create-drop
spring.jpa.show-sql=true
```
