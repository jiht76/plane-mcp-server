import os
import time

import httpx
from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from fastmcp.utilities.logging import get_logger
from starlette.authentication import (
    AuthenticationBackend,
    AuthCredentials,
    AuthenticatedUser,
)
from starlette.requests import HTTPConnection
from starlette.middleware import Middleware
from starlette.authentication import AuthenticationMiddleware

logger = get_logger(__name__)

DEFAULT_PLANE_BASE_URL = "https://api.plane.so"


class PlaneAPIKeyAuthBackend(AuthenticationBackend):
    """Authentication backend that reads the Plane PAT from x-api-key."""

    def __init__(self, token_verifier: TokenVerifier):
        self.token_verifier = token_verifier

    async def authenticate(self, conn: HTTPConnection):
        # Read x-api-key directly from the request headers.
        api_key = next(
            (
                conn.headers.get(key)
                for key in conn.headers
                if key.lower() == "x-api-key"
            ),
            None,
        )

        if not api_key:
            return None

        # Validate the Plane PAT through our TokenVerifier.
        auth_info = await self.token_verifier.verify_token(api_key)

        if not auth_info:
            return None

        if auth_info.expires_at and auth_info.expires_at < int(time.time()):
            return None

        return AuthCredentials(auth_info.scopes), AuthenticatedUser(auth_info)


class PlaneHeaderAuthProvider(TokenVerifier):
    def __init__(
        self,
        required_scopes: list[str] | None = None,
        timeout_seconds: int = 10,
    ):
        super().__init__(required_scopes=required_scopes)
        self.timeout_seconds = timeout_seconds

    def get_middleware(self) -> list:
        """Use x-api-key instead of Authorization: Bearer."""
        return [
            Middleware(
                AuthenticationMiddleware,
                backend=PlaneAPIKeyAuthBackend(self),
            ),
        ]

    async def _validate_api_key(self, token: str) -> bool:
        """Validate the API key by calling the Plane API."""
        base_url = (
            os.getenv("PLANE_INTERNAL_BASE_URL")
            or os.getenv("PLANE_BASE_URL", DEFAULT_PLANE_BASE_URL)
        ).rstrip("/")

        user_url = f"{base_url}/api/v1/users/me/"

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds
            ) as client:
                response = await client.get(
                    user_url,
                    headers={
                        "x-api-key": token,
                        "Content-Type": "application/json",
                    },
                )

                if response.status_code != 200:
                    logger.warning(
                        "API key validation failed: %s",
                        response.status_code,
                    )
                    return False

                return True

        except httpx.RequestError as e:
            logger.warning(
                "API key validation request failed: %s",
                e,
            )
            return False

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            from fastmcp.server.dependencies import get_http_headers

            headers = get_http_headers()

            workspace_slug = headers.get("x-workspace-slug")

            if not workspace_slug:
                logger.warning(
                    "x-api-key header found but x-workspace-slug is missing"
                )
                return None

            if not await self._validate_api_key(token):
                logger.warning(
                    "API key validation against Plane API failed"
                )
                return None

            logger.info(
                "API key validated successfully via Plane API"
            )

            expires_at = int(time.time() + 3600)

            return AccessToken(
                token=token,
                client_id="api_key_header_user",
                scopes=["read", "write"],
                expires_at=expires_at,
                claims={
                    "auth_method": "api_key_header",
                    "workspace_slug": workspace_slug,
                },
            )

        except RuntimeError:
            logger.debug(
                "No active HTTP request available for header check"
            )
            return None
