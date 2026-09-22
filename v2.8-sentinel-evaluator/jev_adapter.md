# Jev → U1 Sentinel adapter

This adapter integrates typesafe-ai/jev through the Vercel AI Gateway as an advisory evaluator.

## Security invariant

Jev output is not authority.

Jev can return allow, deny, or manual_review, but it cannot grant permissions, change the proposal, bypass policy, or execute an effect.

The existing deterministic Sentinel path remains authoritative:

deterministic DENY => DENY

Jev ALLOW + deterministic ALLOW still requires confirmation, nonce consumption, proposal revalidation, and final deterministic policy.

## Environment

Create an AI Gateway key with the Vercel CLI:

vercel ai-gateway api-keys create --name u1-jev-evaluator

Set the printed key as:

export AI_GATEWAY_API_KEY="..."

For Vercel deployment, store it as a server-side environment variable. Never expose it to browser code.

## Dependency

The adapter expects the Vercel AI SDK:

npm install ai

## Contract mapping

Jev evaluates three boolean questions:

- evidence_sufficient
- hazardous
- human_review

The adapter deterministically maps those typed answers into the existing Sentinel evaluator contract.

It deliberately does not ask Jev whether the principal is authorized. Authorization remains a deterministic server-side fact.

## Production boundary

The adapter is not a replacement for:

- principal authentication
- permission evaluation
- resource classification
- proposal immutability
- confirmation binding
- nonce replay protection
- final policy evaluation
- deterministic execution

Those controls stay in sentinel_control.py.
