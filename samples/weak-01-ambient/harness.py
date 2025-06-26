#!/usr/bin/env python3
"""Runnable stub of weak-01-ambient.

Not a model. A loop that executes whatever tool call appears in the
"model" output, where the model is a regex. It exists so the manifest
can be checked against something that behaves the way the manifest
says it does, and so the sample's findings can be demonstrated rather
than asserted.

Every tool here is inert. send_email appends to a file; fetch_url
records the URL and returns a fixed body. A sample harness that sends
real mail would be a worse idea than the vulnerability it demonstrates.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

HERE = Path(__file__).parent
OUTBOX = HERE / "outbox.jsonl"
FETCHED = HERE / "fetched.jsonl"

CUSTOMERS = {
    "1001": {"tenant": "alice", "name": "Ada", "plan": "pro"},
    "1002": {"tenant": "bob", "name": "Grace", "plan": "free"},
}

CALL_RE = re.compile(r"CALL (\w+)\((.*)\)")


def lookup_customer(customer_id: str, tenant_id: str) -> dict:
    # The tenant check reads an argument the caller supplied. The
    # caller is the model.
    rec = CUSTOMERS.get(customer_id)
    if rec is None or rec["tenant"] != tenant_id:
        return {"error": "not found"}
    return rec


def send_email(to: str, body: str) -> dict:
    with OUTBOX.open("a") as fh:
        fh.write(json.dumps({"to": to, "body": body}) + "\n")
    return {"status": "queued"}


def fetch_url(url: str) -> dict:
    with FETCHED.open("a") as fh:
        fh.write(json.dumps({"url": url}) + "\n")
    return {"status": 200, "body": "(inert sample body)"}


TOOLS = {"lookup_customer": lookup_customer,
         "send_email": send_email,
         "fetch_url": fetch_url}


def fake_model(context: str) -> str:
    """Follow the last CALL directive in the context, if any."""
    calls = CALL_RE.findall(context)
    if calls:
        name, args = calls[-1]
        return f"CALL {name}({args})"
    return "I can help with that."


def run(task: str, documents: list[str], steps: int = 8) -> list[dict]:
    # Session-scoped authority: granted once, here, and then spent by
    # whatever the loop decides for the rest of the run.
    context = ["SYSTEM: You are a support assistant for ACME.",
               f"USER: {task}"]
    context += [f"DOCUMENT: {d}" for d in documents]
    trace = []
    for _ in range(steps):          # no budget in the manifest either
        out = fake_model("\n".join(context))
        m = CALL_RE.match(out)
        if not m:
            trace.append({"proposed": out, "result": None})
            break
        name, raw = m.group(1), m.group(2)
        kwargs = dict(kv.split("=", 1) for kv in raw.split(",") if kv)
        result = TOOLS[name](**{k.strip(): v.strip().strip("\"'")
                                for k, v in kwargs.items()})
        # Trace records the proposal and the result, and nothing about
        # provenance, authorisation or the arguments actually used.
        trace.append({"proposed": name, "result": result})
        context.append(f"TOOL RESULT: {json.dumps(result)}")
    return trace


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--document", action="append", default=[])
    args = ap.parse_args()
    for row in run(args.task, args.document):
        print(json.dumps(row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
