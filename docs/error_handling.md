# SecAgents AI Gateway — Error Handling Design

## Overview

The SecAgents AI gateway processes selected Wazuh alerts and sends approved alert information to a locally hosted Ollama model for analysis.

The gateway must handle errors without affecting Wazuh detection or modifying the original security evidence.

## Timeout Handling

THe gateway will have configurable connection and response timeouts when talking with Ollama.

Initial development values:

- Connection timeout: 5 seconds
- Response timeout: 120 seconds

Thess values will be adjusted after more testing

If a timeout occurs it will return a controlled Model_Timeout error

## Error handling

The gateway will handle the following errors:

- MODEL_UNAVAILABLE: Ollama cannot be reached or the requested model is unavailable.

- MODEL_TIMEOUT: Ollama does not respond within the configured timeout.

- INVALID_INPUT: The normalized Wazuh event does not satisfy the required input schema.

- INVALID_AI_RESPONSE: The model returns malformed JSON or output that fails schema validation.

- INTERNAL_ERROR: An unexpected application error occurs. Errors will be returned in a consistent JSON format.

Example:

{

  "status": "error",

  "event_id": "example-event-id",

  "event_index": "wazuh-alerts-example",

  "error": {

    "code": "MODEL_TIMEOUT",

    "message": "AI analysis timed out."

  }

}

## Logging 

The gateway will record information including: 

- Timestamp
- Original event ID and index
- Requested model
- Processing status
- Request duration
- Error category when applicable

By default sensitive information, credentials, complete prompts, and raw alert contents will not be logged

## AI Response Validation

All successful model responses must pass the existing validate_ai_response() function in app/schemas.py.

Responses that fail validation will not be presented as successful AI analysis.

## Fail-Closed Behavior 

AI enrichment is advisory and must not affect the original Wazuh alert.

If the process fails: 

1. The original Wazuh alert remains unchanged.
2. Invalid AI output is rejected.
3. No automated security action is performed.
4. The gateway returns a controlled error.
5. The failure is recorded for troubleshooting.
6. Wazuh continues operating independently.

The gateway will not execute commands, change firewall rules, modify Wazuh configurations, or delete security logs.

## Future implimentation

These nehaviors are not currently all implimentated and will be as development continues.

Automated tests will cover unavailable models, timeouts, invalid requests, malformed responses, and successful processing.