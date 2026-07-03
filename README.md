# moab-mcp-core

Общее ядро auth/ролей для MCP-серверов портала moab.tools: верификация Keycloak-токенов
(JWKS RS256), проверка ролей, ASGI-seam `authenticate_request` (401/403) и structured
per-tool-call logging.

## Установка

```bash
pip install -e .[test]
python -m pytest
```

## Конфигурация (env)

| Переменная | Назначение | Дефолт |
|---|---|---|
| `KEYCLOAK_AUTHORITY` | issuer/authority Keycloak | `https://auth.moab.tools/realms/moab` |
| `ALLOWED_ROLES` | роли через запятую; с 0.3.0 — **fallback** для динамических ролей | пусто |
| `MCP_AUDIENCE` | требуемый `aud` (опционально) | не проверяется |
| `PORTAL_RESOURCE` | client в `resource_access` | `moab-portal` |
| `PORTAL_BASE_URL` | базовый URL портала для динамических ролей | не задан |
| `PORTAL_TOOL_SECTION` | секция инструмента в портале | не задан |
| `PORTAL_TOOL_SLUG` | slug инструмента в портале | не задан |
| `PORTAL_ROLES_TTL` | TTL кэша ролей, секунды | `60` |

## Динамические роли (0.3.0)

Если заданы все три `PORTAL_BASE_URL`, `PORTAL_TOOL_SECTION`, `PORTAL_TOOL_SLUG`,
`KeycloakVerifier` тянет актуальные роли инструмента с анонимного портального эндпоинта
`GET {base}/api/tools/{section}/{slug}/allowed-roles` (`PortalRolesProvider`,
прод-URL портала: `http://portal.moab-portal.svc:8080`). Без этих переменных поведение
идентично 0.2.0 (статичный `ALLOWED_ROLES`).

Семантика:

- **env = fallback**: `ALLOWED_ROLES` используется, пока портал ни разу не ответил успешно.
- **stale-while-revalidate**: `authenticate()` синхронный и исполняется в event loop —
  провайдер никогда не ждёт сеть. Синхронный `prime()` выполняется при создании
  verifier'а (до старта uvicorn); дальше — фоновый async-refresh по TTL (60 с).
- **last-known-good**: 404 (инструмент не зарегистрирован/неактивен), сетевые ошибки,
  5xx и битый JSON не затирают последний успешно полученный набор ролей.
- **Пустой `allowedRoles`** валиден и означает «только admin».
- **admin-bypass безусловный**: роль `admin` проходит всегда, независимо от набора
  (зеркалит портальный `ProjectAccessPolicy.HasAccess`).
