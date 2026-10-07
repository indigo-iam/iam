Dear ${recipient},

your account in ${organisationName} has been temporarily locked after too many failed login attempts.

<#if hasLocalPassword>You can try to log in again after ${suspensionDurationMinutes} minutes, or reset your password to unlock your account immediately.

If these login attempts were not made by you, please also contact the administrators.<#else>You can try to log in again after ${suspensionDurationMinutes} minutes.

If these login attempts were not made by you, or you need the suspension revoked sooner, please contact the administrators.</#if>

The ${organisationName} registration service
