"""Social/OAuth/OIDC connector primitives for Coreline Auth.

This package preserves the historic ``coreline_auth.social`` public import path
while splitting connector, discovery, and ID-token verification internals into
small modules.
"""

import httpx as httpx

from ._utils import redact_token_response
from .connectors import DevSocialConnector, FacebookOAuthConnector, GenericOIDCConnector, GoogleOAuthConnector, OAuthConnector
from .discovery import JWKSCache, OIDCMetadataClient, discover_oidc_metadata
from .models import IdTokenClaims, OAuthPKCE, OAuthProviderConfig, OAuthStart, OIDCProviderMetadata, ProviderTokenVault, SocialProfile
from .verification import verify_google_id_token, verify_oidc_id_token

__all__ = [
    "DevSocialConnector",
    "FacebookOAuthConnector",
    "GenericOIDCConnector",
    "GoogleOAuthConnector",
    "IdTokenClaims",
    "JWKSCache",
    "OAuthConnector",
    "OAuthPKCE",
    "OAuthProviderConfig",
    "OAuthStart",
    "OIDCMetadataClient",
    "OIDCProviderMetadata",
    "ProviderTokenVault",
    "SocialProfile",
    "discover_oidc_metadata",
    "redact_token_response",
    "verify_google_id_token",
    "verify_oidc_id_token",
]
