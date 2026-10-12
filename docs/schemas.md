# SecAgents - Wazuh and AI Data Schemas

## Overview

This is the initial setup for how we're going to handle Wazuh alerts and AI responses in SecAgents.

Since Wazuh alerts don't always contain the same information, I needed a way to pull out the fields we're interested in and put them into a consistent format before they get sent to the AI model.

I started with two Python files:

- `app/normalizer.py` - Pulls information from the original Wazuh alert and organizes it into a standard format.
- `app/schemas.py` - Validates the normalized alerts and the responses we'll eventually get back from the AI.

Right now, these handle the data formatting and validation. The actual connection to the local AI model is still being worked on.

## Wazuh Input

We're using the existing Wazuh integration on the AI server to retrieve alerts.

The alerts include information like the hostname, severity, rule ID, and a description of what triggered the alert. Depending on the event, they can also include IP addresses, MITRE ATT&CK techniques, or additional details.

Here's a sample file integrity alert based on the structure we're receiving:

```json
{
  "index": "wazuh-alerts-example",
  "document_id": "test-001",
  "alert": {
    "@timestamp": "2026-10-08T16:57:36.956Z",
    "agent": {
      "name": "test-server",
      "ip": "192.0.2.10"
    },
    "rule": {
      "id": "550",
      "level": 7,
      "description": "Integrity checksum changed.",
      "mitre": {
        "id": ["T1565.001"]
      }
    },
    "syscheck": {
      "path": "/etc/example/test.conf",
      "event": "modified"
    }
  }
}
```

This alert is reporting that Wazuh detected a change to a monitored file.

## Normalizing Wazuh Alerts

The `normalize_alert()` function takes the original alert and extracts the fields we need.

For the example above, the normalized event would look like this:

```json
{
  "event_id": "test-001",
  "event_index": "wazuh-alerts-example",
  "timestamp": "2026-10-08T16:57:36.956Z",
  "hostname": "test-server",
  "agent_ip": "192.0.2.10",
  "source_ip": null,
  "severity": 7,
  "severity_label": "Medium",
  "rule_id": "550",
  "description": "Integrity checksum changed.",
  "mitre_ids": ["T1565.001"],
  "event_type": "file_integrity",
  "details": {
    "file_path": "/etc/example/test.conf",
    "file_action": "modified",
    "changed_attributes": [],
    "process": null
  }
}
```

I also added severity labels so we don't have to rely only on Wazuh's numerical severity levels.

| Wazuh Level | Label |
|---|---|
| 0-6 | Low |
| 7-11 | Medium |
| 12-14 | High |
| 15-16 | Critical |

One thing I had to account for was the difference between the agent IP and source IP.

The `agent_ip` is the address of the monitored system, while `source_ip` is the address associated with the activity that triggered the alert. These aren't necessarily the same.

Not every Wazuh alert contains a source IP, so the normalizer sets it to `null` when one isn't available.

I also kept the original document ID and index so we can reference the actual Wazuh event later instead of relying only on the AI's explanation.

For now, the normalizer has additional handling for file integrity alerts. Other event types will need to be added as we work through the integration.

## Event Validation

After normalizing an alert, we use `validate_event()` in `schemas.py` to check that the data is formatted correctly.

These are the main fields we're checking:

| Field | Expected Type |
|---|---|
| `event_id` | String |
| `timestamp` | String |
| `hostname` | String |
| `severity` | Integer |
| `severity_label` | String |
| `rule_id` | String |
| `description` | String |
| `mitre_ids` | List of strings |
| `details` | Dictionary |
| `event_index` | String or null |
| `source_ip` | String or null |

The validator checks that required fields exist and contain the correct data types. It also makes sure the severity is between 0 and 16 and uses one of our supported severity labels.

The `event_index` and `source_ip` fields are optional, but their values are checked when they're included.

If something doesn't match the expected format, the validator raises a `SchemaValidationError`.

## AI Response Schema

The next part is defining what we expect the local Qwen model to return.

We haven't connected the model to this code yet, but I wanted to have the response format ready before starting that integration.

Here's the current response structure:

```json
{
  "event_id": "test-001",
  "event_index": "wazuh-alerts-example",
  "summary": "A monitored configuration file was modified.",
  "source_context": "The change was detected on test-server.",
  "classification": "unknown",
  "confidence": 0.65,
  "uncertainty": "The alert does not establish whether the change was authorized.",
  "mitre_explanation": "The alert references MITRE ATT&CK technique T1565.001.",
  "recommended_actions": [
    "Review the file modification history.",
    "Verify whether the change was authorized."
  ],
  "evidence": [
    "Wazuh rule 550 detected a file integrity change."
  ]
}
```

The main things we want from the AI are a short summary of the alert, some context about the source, and recommendations for what an analyst should look into.

I also included an uncertainty field because the model won't always have enough information to determine whether something is actually malicious.

For example, Wazuh might report that a configuration file changed, but that doesn't automatically mean someone made an unauthorized change.

The response also includes:

- `classification` - Benign, suspicious, malicious, or unknown.
- `confidence` - A number between 0 and 1.
- `mitre_explanation` - An explanation of the MITRE technique if one is associated with the alert.
- `recommended_actions` - Steps an analyst could take to investigate.
- `evidence` - Information from the original alert supporting the analysis.

The original event ID and index are included so we can connect the AI's analysis back to the Wazuh alert. When we build the gateway, those identifiers should come from the original event rather than relying on the model to generate them.

The AI won't be responsible for changing Wazuh's original severity or automatically taking action against monitored systems.

## AI Response Validation

I also created `validate_ai_response()` to check the response structure.

It checks that the required fields are present, the classification uses one of our supported values, and confidence is between 0 and 1.

The recommendations and evidence also need to be lists of strings.

The MITRE explanation is optional because some alerts don't include MITRE information. It can be a string, `null`, or omitted.

This validation only checks the format of the response. It doesn't confirm whether the AI's conclusions are accurate or whether the evidence actually supports them.

We'll need to handle that separately when building the gateway.

## Testing

I wrote unit tests for the normalizer and both validation functions.

So far, the tests cover severity labels, file integrity alerts, missing optional fields, source IP extraction, event references, and invalid data.

I also added tests for the AI response fields, including classification, confidence, uncertainty, and MITRE explanations.

To run the tests:

```bash
python3 -m unittest discover -s tests -v
```

**Current results: 21 tests passed locally on my Mac.**

An earlier version of the code passed 13 tests on the AI server. I still need to pull the latest changes onto that server and rerun the updated tests.

I also used the existing Wazuh connection to retrieve real alerts and test the normalizer against them.

The file integrity alert I tested was successfully normalized and passed validation. That test was done before the latest schema changes, so I'll repeat it after updating the server.

## Next Steps

The input and output formats are now drafted, and the validation functions are passing their current tests.

The remaining work is to get the AI gateway connected and start using these schemas with the actual model.

My next steps are:

1. Have the SIEM and Documentation team members review the schemas.
2. Push the latest code to GitHub and test it on the AI server.
3. Confirm the Python application can communicate with Qwen through the approved API.
4. Connect the normalized Wazuh alerts to the AI gateway.
5. Validate the responses coming back from the model.
6. Add timeout handling, error logging, and fail-closed behavior.

The schemas are ready for an initial review, but the full Wazuh-to-AI workflow hasn't been implemented or tested yet.