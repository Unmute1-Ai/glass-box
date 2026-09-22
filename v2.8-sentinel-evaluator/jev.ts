import { experimental_evaluate as evaluate } from "ai";

type Risk = "low" | "medium" | "high" | "critical";
type Verdict = "allow" | "deny" | "manual_review";

export interface JevReviewContext {
  proposal: Record<string, unknown>;
  proposal_digest: string;
  effective_permissions: string[];
  resource_classification: Record<string, string>;
  policy_version: string;
  authority_effect: "none";
}

export interface JevReview {
  verdict: Verdict;
  risk: Risk;
  findings: string[];
  model: "typesafe-ai/jev";
  authority_effect: "none";
}

function boolAnswer(result: any, key: string): boolean {
  const value = result?.answers?.[key];
  if (typeof value === "boolean") return value;
  if (typeof value?.value === "boolean") return value.value;
  throw new Error("jev_boolean_answer_missing:" + key);
}

export async function reviewWithJev(
  context: JevReviewContext,
): Promise<JevReview> {
  const result = await evaluate({
    model: "typesafe-ai/jev",
    state: JSON.stringify(context),
    questions: {
      evidence_sufficient: {
        type: "boolean",
        instructions:
          "Is the supplied evidence sufficient to identify the exact proposed action and its relevant security constraints? Do not infer authorization.",
      },
      hazardous: {
        type: "boolean",
        instructions:
          "Does the evidence identify a material security, safety, privacy, integrity, or scope hazard in the proposed action?",
      },
      human_review: {
        type: "boolean",
        instructions:
          "Does the evidence contain unresolved ambiguity that should require human review before execution?",
      },
    },
  });

  const sufficient = boolAnswer(result, "evidence_sufficient");
  const hazardous = boolAnswer(result, "hazardous");
  const humanReview = boolAnswer(result, "human_review");

  if (!sufficient) {
    return {
      verdict: "manual_review",
      risk: "high",
      findings: ["Jev found the supplied evidence insufficient to support a bounded evaluation."],
      model: "typesafe-ai/jev",
      authority_effect: "none",
    };
  }

  if (humanReview) {
    return {
      verdict: "manual_review",
      risk: hazardous ? "high" : "medium",
      findings: [
        "Jev identified unresolved ambiguity requiring human review.",
        ...(hazardous ? ["Jev also identified a material hazard."] : []),
      ],
      model: "typesafe-ai/jev",
      authority_effect: "none",
    };
  }

  if (hazardous) {
    return {
      verdict: "deny",
      risk: "high",
      findings: ["Jev identified a material security, safety, privacy, integrity, or scope hazard."],
      model: "typesafe-ai/jev",
      authority_effect: "none",
    };
  }

  return {
    verdict: "allow",
    risk: "low",
    findings: ["Jev found no material hazard in the supplied evidence."],
    model: "typesafe-ai/jev",
    authority_effect: "none",
  };
}
