from starlette.requests import Request
from starlette.responses import JSONResponse

from .auth import AuthError, KeycloakVerifier, TokenClaims


def make_unauthorized_response(resource_metadata_url: str, status: int = 401,
                               message: str = "Unauthorized") -> JSONResponse:
    headers = {}
    if status == 401:
        headers["WWW-Authenticate"] = f'Bearer resource_metadata="{resource_metadata_url}"'
    return JSONResponse({"error": message}, status_code=status, headers=headers)


def authenticate_request(verifier: KeycloakVerifier, request: Request,
                         resource_metadata_url: str) -> TokenClaims | JSONResponse:
    try:
        return verifier.authenticate(request.headers.get("authorization"))
    except AuthError as e:
        return make_unauthorized_response(resource_metadata_url, status=e.status, message=e.message)
