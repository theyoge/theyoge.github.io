---
layout: post
title: "Your First Bug Bounty with Hermes Agent: A Beginner’s Field Guide"
date: 2026-10-22 12:00:00 +0530
categories: [security, ai]
tags: [bug-bounty, penetration-testing, hermes-agent, kali-linux, web-security, api-security, ai-agents]
description: "A practical, beginner-friendly guide to using Hermes Agent as a careful bug-bounty copilot: set up models, define scope, practice locally, test responsibly, and turn evidence into a clear report."
---

<img class="post-hero" src="/assets/img/hermes-bugbounty.svg" alt="Hermes Agent coordinates a scoped security test, with a human researcher reviewing evidence" width="1200" height="380">

Bug bounty can look like a wall of tools: terminal windows, subdomain lists, scanners, API clients, and write-ups full of acronyms. It is easy to mistake *more commands* for *better research*.

The more useful starting point is a repeatable process: understand the rules, choose one small question, gather evidence carefully, and stop when you have a safe reproduction. [Hermes Agent](https://hermes-agent.nousresearch.com/) can help organize that process. It can read your notes, use enabled tools, run bounded tasks, and ask a second model to handle a well-defined subtask. It is an assistant—not an authorization system, not a source of truth, and not a substitute for your judgment.

This guide takes you from a fresh Hermes conversation to a first practice assessment. The hands-on target is a local training app bound to your own computer. For a real program, use its current published rules and exact scope; examples below deliberately name no real target.

## First, what Hermes does—and what it does not

Hermes is an agent: a language model that can call tools you have enabled, inspect the results, and decide what to do next. Depending on your setup, those tools may include file operations, a terminal, browser controls, web search, or delegated subagents. Tool availability varies by configuration. [Hermes’ tool reference](https://hermes-agent.nousresearch.com/docs/reference/tools-reference) lists the built-in toolsets.

That extra agency is useful, but it changes the risk. A chatbot that gives a bad suggestion is one thing; an agent with a terminal can act on it. Start with a narrow task, a bounded workspace, and a clear target boundary. Don’t paste API keys, session cookies, customer data, or private reports into prompts. Don’t give an agent access to an account or system you are not authorized to test.

## The two-model pattern: planner and worker

One practical arrangement is a stronger main model for planning and synthesis, plus a lower-cost model for discrete delegated work. In Hermes, `delegate_task` runs child agents with their own fresh conversations; they do not automatically know the parent’s previous discussion. Give each child enough context to do exactly one job, and ask the main agent to review the result. [Hermes delegation guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/delegation) explains the hand-off.

For example, a parent might ask one child to summarize an API schema and another to classify a set of *already collected* endpoints by likely authentication boundary. The parent can compare those summaries and decide what to inspect next. Delegation is not a permission bypass: children inherit tools, and their work still has to stay within the same authorized scope.

Keep the first setup simple. Hermes’ interactive model picker is:

```bash
hermes model
```

Choose a provider and model you can authenticate to, then verify an ordinary chat before layering on tools or delegation. Hermes keeps model/provider settings in its config and credentials separately; use the CLI’s auth/setup flow rather than putting secrets in a prompt or a project file. For current setup choices, use the [Hermes quickstart](https://hermes-agent.nousresearch.com/docs/getting-started/quickstart) and [model configuration guide](https://hermes-agent.nousresearch.com/docs/user-guide/configuring-models).

Once the main model works, configure a delegated provider/model if you want one. Make the first delegation harmless and easy to verify—for instance, ask a child to return a fixed phrase. Check that it completed, then use a small research task. Avoid starting with a batch of scans or a long autonomous job.

## Before a real assessment: build a scope card

Scope is not “everything that looks related.” It is the exact set of assets and activities a program authorizes, plus its exclusions and testing conditions. A wildcard, if present, means only what that program says it means. A link from an in-scope site, a certificate entry, shared hosting, or a DNS result does not automatically add a new target.

Before any active testing, collect the current program brief and create a short scope card for the working session. Include:

- **Allowed assets:** copy exact domains, URL patterns, application names, and IP ranges from the live brief.
- **Out-of-scope assets:** record exclusions and third-party services explicitly.
- **Allowed methods:** note rate limits, account requirements, prohibited tests, and any special handling for APIs or infrastructure.
- **Data boundaries:** use only accounts and data you own or are authorized to use; define what to do if sensitive information appears.
- **Stop conditions:** service instability, unexpected access to another person’s data, ambiguous ownership, or a test that could alter or delete real data.

Ask Hermes to restate the scope card and identify anything ambiguous before it acts. This is not a request for permission before each ordinary in-scope step; it is a check that the task has a well-defined boundary. If the program rules are unclear or conflicting, pause that activity and resolve the uncertainty through the program’s official channel.

## Practice safely on your own machine

You do not need a public target to learn an agent workflow. OWASP Juice Shop is an intentionally vulnerable training application. This command publishes it only on the local loopback interface, so other devices on your network cannot connect through that port:

```bash
docker run --rm -d \
  --name juice-shop \
  -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop
```

Open `http://127.0.0.1:3000` in your browser. When you finish, stop and remove the container:

```bash
docker stop juice-shop
```

Start Hermes from a dedicated practice directory. Keep only lab notes and files you intend it to inspect there. You can use `hermes` for the classic interface or `hermes --tui` for the newer terminal interface. [The quickstart](https://hermes-agent.nousresearch.com/docs/getting-started/quickstart) covers the CLI and setup flow.

Try a staged conversation rather than one giant “find everything” command:

**1. Plan first**

> I’m practicing against my local Juice Shop instance at http://127.0.0.1:3000, which I started on this machine. First, propose a beginner-friendly web testing plan. Do not send requests yet. Keep it low impact and list what evidence would confirm or refute each idea.

**2. Make the boundary explicit**

> The only target for this exercise is http://127.0.0.1:3000. Do not follow links or test other hosts. Use only this local lab. Avoid destructive actions, bulk submissions, brute force, and denial-of-service testing. If a step could change or delete data, stop and explain the risk.

**3. Work one hypothesis at a time**

> Inspect the app’s visible behavior and identify one low-risk access-control question to test using only the local lab. Explain the request you plan to make and the expected safe evidence before sending it.

**4. Review the result**

> Summarize what happened, separate observations from assumptions, and tell me what additional evidence would be needed before calling this a vulnerability. Do not claim a finding based only on a scanner label.

These prompts are deliberately specific. They give Hermes an objective, a boundary, and a stop condition. If the result is unexpected, ask it to explain the evidence instead of immediately escalating to more intrusive tests.

## The real bug-bounty loop

After you are comfortable in a lab, the same structure can be used for a program where you are an eligible participant and the target is explicitly in scope. The difference is that real systems contain other users and real data, so the cost of a careless action is much higher.

### 1. Read the rules before touching the target

Use the program’s current policy—not an old note or a search result. Check allowed assets, exclusions, testing windows, request limits, account rules, and disclosure requirements. Treat every discovered hostname as out of scope until it matches the published target definition. If a target’s ownership or scope is ambiguous, do not probe it.

### 2. Map, then choose a question

Start with a small inventory from authorized program material: application entry points, API documentation, authentication roles, and features you can reach with your own account. Keep passive collection distinct from active requests. Then select one testable security question, such as whether a user can access an object they created under a different role in an account you control.

Do not turn “map the surface” into an excuse for indiscriminate scanning. Keep network checks to specifically authorized ranges and conservative rates. A large scan can affect availability, trigger defenses, or reach infrastructure the program does not control.

### 3. Test with your own accounts and minimal data

For web and API work, keep a record of the request, response, account role, and object ownership. Change one variable at a time. Use two accounts only when the program permits it and both are yours or explicitly authorized. Avoid accessing or exporting another person’s data to prove impact.

For every hypothesis, ask: “What is the smallest safe action that would prove this?” A single controlled read may be enough. Do not create persistence, alter production records, send messages to real users, or retrieve a large dataset just to make a report look more convincing.

### 4. Stop on sensitive data or instability

If a response unexpectedly exposes personal, regulated, or secret information, stop interacting with it. Don’t copy it into notes, send it to a model, or retain it as evidence; follow the program’s reporting instructions. Stop active work if the service becomes unstable, if the next step could cause harm, or if scope is no longer clear.

### 5. Verify and report

A tool’s output is a lead, not a confirmed vulnerability. Reproduce the behavior with the smallest safe proof, note the exact conditions, and explain the real security impact. A useful report contains a concise title, affected in-scope asset, prerequisites, numbered reproduction steps, expected versus actual behavior, impact, and focused remediation advice. Include only evidence you are allowed to retain. Submit through the program’s required channel and follow its coordinated-disclosure terms.

## Turn the workflow into project instructions

Hermes can load project context from files such as `AGENTS.md` when you launch it in that workspace. A project instruction file can keep recurring boundaries close to the work. Keep it short and factual:

```markdown
# Authorized assessment workspace
- Use only the assets listed in the current program scope file.
- Never infer scope from DNS, certificates, links, or apparent ownership.
- Use only accounts and data I own or am authorized to test.
- Keep requests low-rate and non-disruptive; no brute force or DoS.
- Stop if personal or regulated data appears, or if scope is ambiguous.
- Save concise notes; do not store secrets or third-party data.
```

This file is a reminder, not a technical sandbox. It cannot prevent every mistake or override the program’s rules. Use operating-system permissions, an isolated VM/container, a dedicated browser profile, and narrowly scoped credentials to reduce what an agent can reach. If you enable a local terminal, remember that its commands can affect the machine it runs on; keep valuable personal files and secrets outside the testing workspace.

## A reusable starter prompt

For an authorized program, adapt this prompt only after reading the current rules:

> Read the current program scope and rules in this workspace. Summarize the exact in-scope assets, exclusions, rate limits, account requirements, and stop conditions. Work only on those assets and only with accounts/data I own or am authorized to use. Start with a low-impact web/API plan, then proceed with conservative checks that the policy permits. Do not expand scope from DNS, links, certificates, or shared hosting. Stop immediately if sensitive data appears, service stability is affected, or authorization is unclear. Keep evidence minimal and write a factual report draft; do not submit or disclose it for me.

You can ask the main model to delegate a bounded subtask, such as reviewing documentation or checking a set of notes for missing evidence. State the same scope and data rules in the child’s context. A subagent starts with a fresh conversation, so never assume it knows what you told the parent earlier.

## What “good” looks like

The goal is not to let an agent run wild. It is to make careful research less tedious while keeping the researcher accountable. A good first session ends with a scope summary, a short plan, a handful of verified observations, and a clear list of what remains uncertain. A good finding is reproducible, in scope, and supported by minimal evidence. A good stop is also a result: it means the next step needs more authorization, safer test data, or a better understanding of the system.

Start in a lab. Learn how Hermes plans, uses tools, and reports uncertainty. Then bring that disciplined workflow—not a copied pile of commands—to research you are explicitly authorized to do.
