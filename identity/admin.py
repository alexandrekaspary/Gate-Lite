from django.contrib import admin
from .models import (
    AuditEvent, AuthorizationCode, ClientRole, ClientScopeAssignment, ClientSecret, MFAChallenge,
    ClientURI, ClientWebOrigin, GroupClientRoleAssignment, OIDCClient, OIDCScope,
    OIDCSession, RefreshToken, RevokedAccessToken, SecurityPolicy,
    ServiceAccountRoleAssignment, SigningKey, UserClientRoleAssignment, UserEmailState, UserMFA, UserSecurityState,
)

for model in (OIDCClient,ClientRole,UserClientRoleAssignment,GroupClientRoleAssignment,
              ServiceAccountRoleAssignment,ClientURI,ClientWebOrigin,OIDCScope,
              ClientScopeAssignment,ClientSecret,OIDCSession,AuthorizationCode,
              RefreshToken,RevokedAccessToken,SigningKey,SecurityPolicy,AuditEvent,UserMFA,UserSecurityState,UserEmailState,MFAChallenge):
    admin.site.register(model)
