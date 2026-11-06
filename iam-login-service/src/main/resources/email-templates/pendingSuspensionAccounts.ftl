Dear administrator,

The following users are currently in PENDING_SUSPENSION state and will be suspended after
${suspensionGracePeriodDays} days if no action is taken:

<#list accounts as entry>
- Name: ${entry.account.userInfo.name}
  Username: ${entry.account.username}
  Email: ${entry.account.userInfo.email}
  Expiration date: ${entry.expirationDateTime}
  Suspension date: ${entry.suspensionDateTime}
  Time left: ${entry.daysLeft} days, ${entry.hoursLeft} hours, ${entry.minutesLeft} minutes
</#list>

The ${organisationName} registration service


