Dear ${recipient},

Your account in ${organisationName} has been temporarily locked after too many failed login attempts.

<#if hasLocalPassword>
You can try to log in again after ${durationInMinutes} minutes or reset your password to unlock your account immediately.
<#else>
You can try to log in again after ${durationInMinutes} minutes.
</#if>

If you need the suspension revoked sooner, please contact the administrators.

The ${organisationName} registration service
