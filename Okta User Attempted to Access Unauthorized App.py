# DD Requirements
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.security_monitoring_api import SecurityMonitoringApi
from datadog_api_client.v2.model.security_monitoring_rule_case_create import SecurityMonitoringRuleCaseCreate
from datadog_api_client.v2.model.security_monitoring_rule_evaluation_window import (
    SecurityMonitoringRuleEvaluationWindow,
)
from datadog_api_client.v2.model.security_monitoring_rule_keep_alive import SecurityMonitoringRuleKeepAlive
from datadog_api_client.v2.model.security_monitoring_rule_max_signal_duration import (
    SecurityMonitoringRuleMaxSignalDuration,
)
from datadog_api_client.v2.model.security_monitoring_rule_options import SecurityMonitoringRuleOptions
from datadog_api_client.v2.model.security_monitoring_rule_query_aggregation import (
    SecurityMonitoringRuleQueryAggregation,
)
from datadog_api_client.v2.model.security_monitoring_rule_severity import SecurityMonitoringRuleSeverity
from datadog_api_client.v2.model.security_monitoring_rule_type_create import SecurityMonitoringRuleTypeCreate
from datadog_api_client.v2.model.security_monitoring_standard_rule_create_payload import (
    SecurityMonitoringStandardRuleCreatePayload,
)
from datadog_api_client.v2.model.security_monitoring_standard_rule_query import SecurityMonitoringStandardRuleQuery
body = SecurityMonitoringStandardRuleCreatePayload(
    name="Okta User Attempted to Access Unauthorized App",
    # Here is where you will build the detection query
    queries=[
        SecurityMonitoringStandardRuleQuery(
            # Should be the same format as when searching via logs i.e. source:okta @usr.email:christopher@regentmarkets.com @network.client.ip:1.1.1.1
            query="source:okta @evt.name:app.generic.unauth_app_access_attempt",
            # Typically no changes are made here
            aggregation=SecurityMonitoringRuleQueryAggregation.COUNT,
            # Typically is grouped by @usr.email or @evt.name but can be grouped by others.
            group_by_fields=[
                "@usr.email"
            ],
            distinct_fields=[],
            name="unauthorised_app"
        ),
        Se
    ],
    filters=[],
    cases=[
        SecurityMonitoringRuleCaseCreate(
            # Only needed if you have multiple cases
            name="low",
            # Determine the severity of the alert
            status=SecurityMonitoringRuleSeverity.LOW,
            # List what conditions need to be met for the alert to trigger
            condition="unauthorised_app > 0",
            # Setting the tag (staging or prod) and severity should be enough as that automatically applies notification
            notifications=[],
        ),
        SecurityMonitoringRuleCaseCreate(
            # Only needed if you have multiple cases
            name="medium",
            # Determine the severity of the alert
            status=SecurityMonitoringRuleSeverity.MEDIUM,
            # List what conditions need to be met for the alert to trigger
            condition="unauthorised_app > 3",
            # Setting the tag (staging or prod) and severity should be enough as that automatically applies notification
            notifications=[],
        ),

        SecurityMonitoringRuleCaseCreate(
            # Only needed if you have multiple cases
            name="high",
            # Determine the severity of the alert
            status=SecurityMonitoringRuleSeverity.HIGH,
            # List what conditions need to be met for the alert to trigger
            condition="unauthorised_app > 5",
            # Setting the tag (staging or prod) and severity should be enough as that automatically applies notification
            notifications=[],
        ),
    ],
    options=SecurityMonitoringRuleOptions(
        evaluation_window=SecurityMonitoringRuleEvaluationWindow.FIFTEEN_MINUTES,
        keep_alive=SecurityMonitoringRuleKeepAlive.ONE_HOUR,
        max_signal_duration=SecurityMonitoringRuleMaxSignalDuration.ONE_DAY,
    ),
    # Is the title of the alert
    message="## Goal\nDetect when a user is denied access to an app.\n\n## Strategy\nThis rule lets you monitor the following Okta events to detect when a user is denied access to an app:\n\n* `app.generic.unauth_app_access_attempt`\n\n## Triage and response \nPlaybook : https://wikijs.deriv.cloud/en/IT-Admin/nsoc/knowledge-base/okta-maximum-login\n1. Determine whether or not the user should have access to this app.\n2. Contact the user to determine whether they attempted to access this app or whether their account is compromised.\n3. If the user who attempted to log into the app is a shared account check the logs for any user who also tried to log into the same application `{{@target_app}}` at the same time from the same IP `{{@network.client.ip}}`.\n4.  Sample query would be `source:okta @target_app:{{@target_app}} @network.client.ip:{{@network.client.ip}}`.\n5.  If no correlating logs show up escalate to Manager/TL for appropriate action.",
    # Used to add MITRE technique tags & prod/staging tag
    tags=[
        "source:okta",
        "env:NSOC-Production"
    ],
    is_enabled=True,
    # Determine what type of detection is being used (typically LOG_DETECTION)
    type=SecurityMonitoringRuleTypeCreate.LOG_DETECTION,
)

# Used to send the detection rule to DD nothing should be changed here
configuration = Configuration()
with ApiClient(configuration) as api_client:
    api_instance = SecurityMonitoringApi(api_client)
    response = api_instance.create_security_monitoring_rule(body=body)

    print(response)
