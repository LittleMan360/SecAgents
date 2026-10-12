# SecAgents - Wazuh and AI Data Schemas

## Overview

This document explains how SecAgents handles Wazuh alerts and how the data will be passed to the AI model for analysis.

Since Wazuh alerts can contain different information depending on the type of event, we need a consistent format before sending anything to the AI. This makes it easier for the rest of the application to work with the alerts without having to account for every possible Wazuh event structure.

For this part of the project, I created two Python files:

- `normalizer.py` - Takes the original Wazuh alert and extracts the information we need.
- `schemas.py` - Checks that the normalized alert and AI responses contain the correct fields and data types.

The goal is to make sure the AI gateway receives consistent information and that any responses coming back from the model follow a predictable format.

## Wazuh Alert Input

The alerts come from the Wazuh integration already configured on the AI server.

Each alert contains information about the event, such as when it happened, which system it came from, the Wazuh rule that triggered it, and its severity level.

Here is an example of the alert format:

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

This example represents a file integrity alert, where Wazuh detected that a monitored file had changed.

Different types of alerts may contain additional fields or may not include some of the fields shown above.

## Normalizing the Alerts

The purpose of `normalizer.py` is to take the original Wazuh alert and convert it into a simpler structure.

Instead of having the rest of the application search through the original Wazuh JSON, the normalizer pulls out the information we expect to use most often.

For example, the alert above would be converted into:

```json
{
  "event_id": "test-001",
  "timestamp": "2026-10-08T16:57:36.956Z",
  "hostname": "test-server",
  "agent_ip": "192.0.2.10",
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

The normalizer also converts Wazuh severity levels into readable categories:

| Wazuh Level | Category |
|---|---|
| 0-6 | Low |
| 7-11 | Medium |
| 12-14 | High |
| 15-16 | Critical |

Currently, the normalizer also recognizes file integrity alerts and extracts information such as the modified file, the type of change, and the process involved when that information is available.

Other alert types can be added as we continue developing the project.

## Validating Wazuh Events

After an alert is normalized, `schemas.py` checks that the data follows the expected structure.

This is important because we don't want to send incomplete or incorrectly formatted information to the AI model.

The current validation requires the following fields:

| Field | Type | Purpose |
|---|---|---|
| event_id | String | Identifies the Wazuh alert |
| timestamp | String | When the event occurred |
| hostname | String | System that generated the alert |
| severity | Integer | Original Wazuh severity |
| severity_label | String | Readable severity category |
| rule_id | String | Wazuh rule that triggered |
| description | String | Description of the alert |
| mitre_ids | List | Associated MITRE ATT&CK techniques |
| details | Dictionary | Additional event information |

The validator also checks that severity values fall within Wazuh's supported range of 0-16.

If required information is missing or a field contains the wrong type of data, validation fails.

Some fields, such as the agent IP address or event type, may not be available for every alert.

## AI Response Format

Once the normalized event is passed to the AI gateway, the local language model will analyze the alert.

We need the model to return its analysis in a consistent format so that other parts of SecAgents can use the results.

The planned AI response looks like this:

```json
{
  "summary": "A monitored configuration file was modified.",
  "classification": "unknown",
  "confidence": 0.65,
  "recommended_actions": [
    "Review the file modification history.",
    "Verify whether the change was authorized."
  ],
  "evidence": [
    "Wazuh rule 550 detected a file integrity change."
  ]
}
```

The response includes:

- **Summary:** A short explanation of what happened.
- **Classification:** Whether the activity appears benign, suspicious, malicious, or unknown.
- **Confidence:** A value between 0 and 1 representing the model's reported confidence.
- **Recommended actions:** Suggested steps for investigating the event.
- **Evidence:** Information from the alert that supports the analysis.

The AI classification is separate from the original Wazuh severity level. The model should not overwrite the severity assigned by Wazuh.

The recommendations are intended to help with investigations rather than automatically making changes to monitored systems.

## Validating AI Responses

The second function in `schemas.py` checks the information returned by the AI model.

For an AI response to pass validation, it must:

- Include all required fields.
- Use one of the supported classifications.
- Provide a confidence value between 0 and 1.
- Return recommendations and evidence as lists of strings.

If the response doesn't meet these requirements, the validator raises an error.

This helps prevent the application from accepting unexpected or incorrectly formatted responses.

One limitation is that the current validation only checks the structure of the response. It does not verify whether the AI's explanation or evidence is accurate. That will need to be considered when integrating the model.

## Testing

I created automated tests for both the normalizer and schema validation functions.

The tests cover:

- Wazuh severity classification.
- Normalizing file integrity alerts.
- Handling missing optional fields.
- Checking required event fields.
- Rejecting invalid severity values.
- Validating AI classifications and confidence values.
- Rejecting incorrectly formatted AI responses.
- Confirming that normalized alerts pass schema validation.

The tests can be run with:

```bash
python3 -m unittest discover -s tests -v
```

So far, all 13 tests have passed on both my development machine and the AI server.

I also tested the normalizer using real Wazuh alerts retrieved from the existing Wazuh integration.

A real file integrity alert was successfully normalized and passed through the schema validator.

This confirmed that the input processing works with actual Wazuh data, rather than only the sample events used in the automated tests.

## Next Steps

The normalization and validation components are working, but they are only part of the overall AI integration.

The next steps are to:

1. Confirm that the Python application can communicate with the local Qwen model through the approved API connection.
2. Connect the normalized Wazuh events to the AI gateway.
3. Send events to the model and receive structured responses.
4. Validate the model's responses using the existing schema.
5. Implement timeout handling, error logging, and fail-closed behavior.

The AI gateway and local model integration still need to be tested before the complete workflow can be considered functional.