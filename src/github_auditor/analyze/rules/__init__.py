"""Rule registry: every rule class available to the engine."""

from github_auditor.analyze.rules.access_rules import (
    DependabotDisabledRule,
    ForkPrApprovalRule,
    OutsideCollaboratorWriteRule,
    PushProtectionDisabledRule,
    SecretScanningDisabledRule,
    WritableDeployKeyRule,
)
from github_auditor.analyze.rules.base import OrgContext, OrgRule, RepoContext, Rule
from github_auditor.analyze.rules.org_rules import (
    BaseMemberPermissionRule,
    MembersCanCreatePublicReposRule,
    OrgActionsApprovePrRule,
    OrgDefaultTokenWriteRule,
    OrgForkPrApprovalRule,
    TwoFactorNotRequiredRule,
)
from github_auditor.analyze.rules.repo_rules import (
    ActionsUnrestrictedRule,
    ArchivedPublicWorkflowsRule,
    DefaultTokenWriteRule,
    NoBranchProtectionRule,
    PublicSelfHostedRunnerRule,
    StaleActiveActionsRule,
    WeakBranchProtectionRule,
)
from github_auditor.analyze.rules.workflow_rules import (
    CallableReusableWorkflowPermsRule,
    ExternalReusableWorkflowRule,
    MissingPermissionsBlockRule,
    PwnRequestRule,
    ScriptInjectionRule,
    UnpinnedActionRule,
    WorkflowRunTriggerRule,
    WritePermissionsRule,
)

ALL_RULES: list[type[Rule]] = [
    PwnRequestRule,
    UnpinnedActionRule,
    ExternalReusableWorkflowRule,
    WorkflowRunTriggerRule,
    ScriptInjectionRule,
    WritePermissionsRule,
    MissingPermissionsBlockRule,
    CallableReusableWorkflowPermsRule,
    PublicSelfHostedRunnerRule,
    NoBranchProtectionRule,
    WeakBranchProtectionRule,
    StaleActiveActionsRule,
    ArchivedPublicWorkflowsRule,
    DefaultTokenWriteRule,
    ActionsUnrestrictedRule,
    WritableDeployKeyRule,
    OutsideCollaboratorWriteRule,
    SecretScanningDisabledRule,
    PushProtectionDisabledRule,
    DependabotDisabledRule,
    ForkPrApprovalRule,
]

ALL_ORG_RULES: list[type[OrgRule]] = [
    TwoFactorNotRequiredRule,
    BaseMemberPermissionRule,
    OrgForkPrApprovalRule,
    OrgDefaultTokenWriteRule,
    OrgActionsApprovePrRule,
    MembersCanCreatePublicReposRule,
]

__all__ = [
    "ALL_ORG_RULES",
    "ALL_RULES",
    "OrgContext",
    "OrgRule",
    "RepoContext",
    "Rule",
]
