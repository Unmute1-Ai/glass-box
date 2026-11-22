# Industry compatibility track: transparency, audit evidence, and accessible permissions

Status: engineering crosswalk and test plan. This document records proposed compatibility work; it does not claim membership in an external initiative, certification, or completed OS integration.

## 1. Microsoft AI Transparency Initiative crosswalk

Microsoft's November 17, 2026 announcement organizes its initiative around See, Verify, and Control. U1's evidence package should map to those concepts without implying endorsement or participation.

| Microsoft concept | U1 evidence / design target | Evidence boundary |
|---|---|---|
| See: identity, model/runtime, data, tools, actions | Agent/principal identifiers, policy version, tool/action metadata, minimized request and response digests | The frozen v2.7 harness uses mock adapters and synthetic scenarios |
| Verify: evidence independent of the model's account | Independent policy decision, chained receipts, separately verifiable record signatures, completeness claims, external anchors | v2.7 validates its local hash chain; the new completeness helper requires an external signature-verifier callback |
| Control: purpose, owner, delegated authority, pre-effect policy | Principal binding, scoped grants, action-bound confirmation, deterministic deny, final pre-effect policy check | v2.10 is reference code, not a deployed authorization service |
| Model/provider portability | Provider-neutral receipt schema and adapters | Interoperability has not been independently tested against Microsoft products |

**Proposed engineering acceptance criteria**
1. Every consequential tool invocation has a principal, agent identity, action digest, resource/audience, policy version, and decision.
2. The model's own output cannot create or expand authority.
3. A changed action digest, principal, destination, scope, or policy version invalidates the prior approval.
4. A separate verifier can validate the record chain and any signature without trusting the model or agent process.
5. A completeness claim is scoped and time-bounded; absence is never inferred outside a verified scope.
6. Execution evidence is distinct from an authorization receipt. A signed permit does not prove that the external effect occurred as authorized.

Official reference: https://news.microsoft.com/source/2026/11/17/microsoft-and-organizations-across-industries-launch-ai-transparency-initiative-to-strengthen-enterprise-trust-in-ai-models-and-agents/

Microsoft's announcement invites organizations to learn more or sign up at https://aka.ms/learnmoreAItransparency. U1's participation has not been requested or confirmed by this repository change.

## 2. OAuth device-code and agent-session threat model

The new synthetic grant evaluator checks issuer, client ID, principal, exact allowed scopes, expiry, and separate approval for remote-session access. It does not implement RFC 8628 or establish whether a device-code request was initiated by the user.

**Remaining P18 test requirements**
- Bind the device authorization request to the expected issuer and client.
- Preserve a local, user-visible indication of which application initiated the request.
- Reject approval when the requesting client differs from the expected client.
- Enforce minimum scopes and distinguish repository read from write.
- Bind the resulting session to the principal and exact authorization grant.
- Require separate, explicit approval for remote session steering.
- Test one-time consumption and revocation of both the grant and dependent session.
- Test poisoned session memory as untrusted data, never as a source of authorization.

All work must use synthetic clients, tokens, identities, and local fixtures. No real OAuth accounts or third-party services are in scope.

## 3. macOS permission compatibility for assistive technology

Apple's November 16 developer notice describes macOS 27.3 beta 2 changes to Device Control and Data Access, Full Disk Access, and a separate Accessibility permission. Apple says known apps retain their current experience for now; new assistive-technology entitlement details are forthcoming.

**Implementation requirements for any future native U1 macOS component**
- Detect partial permission and handle denial without crashing or entering an unsafe fallback.
- Request only the specific capability needed for the user's chosen task.
- Explain the capability in accessible, plain language before the OS permission prompt.
- Do not conflate Accessibility permission with broad System & App Protection Override.
- Provide an in-app status view and a clear recovery path when permission is revoked.
- Do not repeatedly prompt or pressure the user to grant broader access.
- Keep the user's task and communication preferences available without treating permission denial as user failure.
- Re-test after Apple publishes the final entitlement contract and before claiming compatibility.

A browser PWA that does not invoke these native APIs is not automatically affected. No Apple entitlement request or native integration is part of this track yet.

Official reference: https://developer.apple.com/news/?id=oqng0zjk

## 4. Release and claims boundary

- v2.7-reproducible remains frozen.
- The new AAT/OAuth tests are a separate synthetic evaluator.
- The OAuth helper is a policy test, not a full device-code implementation.
- The AAT helper does not implement cryptographic signing or complete RFC 8785 JCS.
- No Microsoft initiative membership, Apple entitlement, external certification, or production deployment is claimed.
- New tests must be run and reviewed before reporting results.
