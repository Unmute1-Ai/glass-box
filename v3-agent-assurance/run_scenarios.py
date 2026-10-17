"""Run synthetic scenarios and emit a machine-readable JSON report."""
import argparse, json
from pathlib import Path
from agent_watchtower import ActionRequest, AgentWatchtower, policy_from_mapping

def run(path):
    doc=json.loads(Path(path).read_text(encoding="utf-8"))
    gate=AgentWatchtower(policy_from_mapping(doc["policy"])); results=[]
    for case in doc["scenarios"]:
        values=dict(case["request"]); values.setdefault("agent_id","scenario-agent")
        values.setdefault("session_id","session-"+case["id"]); values.setdefault("correlation_id",case["id"])
        values["requested_scope"]=tuple(values.get("requested_scope",()))
        decision=gate.authorize(ActionRequest(**values))
        results.append({"id":case["id"],"expected":case["expected"],"actual":decision.reason,
          "passed":decision.reason==case["expected"],"event_hash":decision.event_hash})
    return {"schema_version":"u1-agent-assurance-report-1","claim_class":doc.get("claim_class"),
      "policy_version":gate.policy.version,"scenario_count":len(results),
      "passed":sum(r["passed"] for r in results),"failed":sum(not r["passed"] for r in results),
      "audit_chain_valid":gate.verify_audit_chain(),"results":results}

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--scenarios",default=str(Path(__file__).with_name("scenarios.json")))
    p.add_argument("--output"); args=p.parse_args(); report=run(args.scenarios)
    rendered=json.dumps(report,indent=2,sort_keys=True)
    if args.output: Path(args.output).write_text(rendered+"\n",encoding="utf-8")
    else: print(rendered)
    raise SystemExit(0 if report["failed"]==0 and report["audit_chain_valid"] else 1)
