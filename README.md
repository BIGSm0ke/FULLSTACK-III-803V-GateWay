# GateWay - API Gateway

Spring Cloud Gateway que centraliza y protege el acceso a los microservicios del sistema FireForce. Implementa autenticación JWT global.

## Tecnologías

- Spring Boot 3.4.4, Spring Cloud Gateway 2024.0.1
- JWT, WebFlux
- JaCoCo, Mockito, JUnit 5, Springdoc OpenAPI

## Rutas

| Ruta Gateway | Destino | Puerto |
|-------------|---------|--------|
| `/api/auth/**`, `/api/users/**` | Micro-Usuarios | 8085 |
| `/api/alerts/**` | Micro-Alertas | 8083 |
| `/api/reports/**` → `/api/reportes/**` | Micro-Reportes | 8084 |
| `/api/monitoreo/**` | Micro-Monitoreo | 8082 |

Swagger: `http://localhost:8080/swagger-ui/index.html`

## Ejecutar

```bash
.\mvnw.cmd spring-boot:run
```

## Pruebas

```bash
.\mvnw.cmd test        # ejecutar tests
.\mvnw.cmd verify      # tests + JaCoCo report
```

Cobertura: **97.0%**

## Capturas

<img width="907" height="107" alt="image" src="https://github.com/user-attachments/assets/49d6fe59-7400-43bc-8b70-d6c56a8b03f6" />

