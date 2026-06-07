"""Coreline Auth public API."""

from .admin import CorelineAdminService
from .async_service import AsyncCorelineAuthService
from .authorization import AuthorizationContext, PermissionDecision, ResourceAuthorizer
from .csrf import CsrfProtector, CsrfToken
from .email import EmailSender, EmailTemplate, EmailTemplateSet, InMemoryEmailSender, RenderedEmail, SentEmailVerification, SentMagicLink, SentPasswordReset, SmtpEmailSender
from .encryption import SecretEnvelopeProtector
from .errors import AuthConfigurationError, AuthenticationFailed, AuthorizationDenied, AuthValidationError, CorelineAuthError, StorageError
from .fastapi_adapter import mount_admin_routes, mount_auth_routes, require_permission, require_session
from .fastapi_async_adapter import mount_async_auth_routes
from .mfa import InMemoryMfaSecretVault, InsecureMfaVaultWarning, MfaSecretVault, generate_totp_secret, totp_code, totp_counter_for_code, verify_totp_code
from .mfa_vault import RedisMfaSecretVault, SQLiteMfaSecretVault
from .models import AuditEvent, AuthAssuranceLevel, AuthCredential, AuthIdentity, AuthMfaFactor, AuthPasskeyChallenge, AuthProfile, AuthRecoveryCode, AuthSession, AuthUser, CredentialType, FlowType, IssuedSession, LoginFlow, MagicLinkChallenge, MfaFactorType, Principal, RequestContext, Role
from .observability import InMemoryMetricSink, JsonLineSecurityEventSink, LoggingMetricSink, MetricSink, PrometheusTextMetricSink
from .permissions import PermissionStatement, PolicyEngine
from .redis_rate_limit import RedisFixedWindowRateLimiter
from .service import CorelineAuthConfig, CorelineAuthService
from .social import DevSocialConnector, FacebookOAuthConnector, GenericOIDCConnector, GoogleOAuthConnector, IdTokenClaims, JWKSCache, OAuthConnector, OAuthPKCE, OAuthProviderConfig, OAuthStart, OIDCMetadataClient, OIDCProviderMetadata, ProviderTokenVault, SocialProfile, discover_oidc_metadata, redact_token_response, verify_google_id_token, verify_oidc_id_token
from .storage import AsyncAuthStorage, AsyncMemoryAuthStorage
from .webauthn import VerifiedPasskeyAssertion, VerifiedPasskeyRegistration, generate_webauthn_challenge, verify_passkey_assertion_response, verify_passkey_registration_response

__all__ = [
    "AsyncAuthStorage", "AsyncCorelineAuthService", "AsyncMemoryAuthStorage", "AuditEvent", "AuthConfigurationError", "AuthAssuranceLevel", "AuthCredential", "AuthIdentity", "AuthMfaFactor", "AuthPasskeyChallenge", "AuthenticationFailed", "AuthorizationContext", "AuthorizationDenied", "AuthProfile", "AuthRecoveryCode", "AuthSession", "AuthUser", "AuthValidationError", "CorelineAdminService", "CorelineAuthConfig", "CorelineAuthError", "CorelineAuthService", "CredentialType", "CsrfProtector", "CsrfToken", "EmailSender", "EmailTemplate", "EmailTemplateSet", "FlowType", "InMemoryEmailSender", "InMemoryMfaSecretVault", "InsecureMfaVaultWarning", "IssuedSession", "LoginFlow", "InMemoryMetricSink", "JsonLineSecurityEventSink", "LoggingMetricSink", "MetricSink", "PrometheusTextMetricSink", "MagicLinkChallenge", "MfaFactorType", "MfaSecretVault", "PermissionDecision", "PermissionStatement", "PolicyEngine", "Principal", "RedisFixedWindowRateLimiter", "RedisMfaSecretVault", "RenderedEmail", "RequestContext", "ResourceAuthorizer", "Role", "SecretEnvelopeProtector", "SentMagicLink", "SentEmailVerification", "SentPasswordReset", "SQLiteMfaSecretVault", "SmtpEmailSender", "DevSocialConnector", "FacebookOAuthConnector", "GenericOIDCConnector", "GoogleOAuthConnector", "IdTokenClaims", "JWKSCache", "OAuthConnector", "OAuthPKCE", "OAuthProviderConfig", "OAuthStart", "OIDCMetadataClient", "OIDCProviderMetadata", "ProviderTokenVault", "SocialProfile", "StorageError", "discover_oidc_metadata", "generate_totp_secret", "redact_token_response", "totp_code", "totp_counter_for_code", "verify_google_id_token", "verify_oidc_id_token", "VerifiedPasskeyAssertion", "VerifiedPasskeyRegistration", "generate_webauthn_challenge", "verify_passkey_assertion_response", "verify_passkey_registration_response", "verify_totp_code", "mount_admin_routes", "mount_async_auth_routes", "mount_auth_routes", "require_permission", "require_session",
]
