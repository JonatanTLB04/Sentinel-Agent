# SENTINEL Agent

AI-powered security triage agent for Datto EDR. Receives alerts via webhook, analyzes them with Claude AI, and automatically takes action in Datto EDR.

## What it does

- Receives real-time alerts from Datto EDR via webhook
- Analyzes each alert using a deterministic triage engine + Claude AI
- Takes automated action based on the decision:
  - **Auto-resolve**: adds a Claude-generated comment, acknowledges the alert, and creates a suppression rule in Datto EDR
  - **Needs review**: adds a comment and surfaces the alert in the dashboard for human review
  - **Escalate**: adds a comment and notifies IT for confirmed threats

## Architecture

Datto EDR -> webhook -> SENTINEL server -> Triage engine -> Claude AI -> Datto EDR API

## Stack

- Node.js + Express
- Anthropic Claude API (claude-sonnet-4-6)
- Datto EDR REST API
- ngrok (local dev tunnel)

## Setup

1. Clone the repo
2. Install dependencies: npm install
3. Create .env file with: ANTHROPIC_API_KEY, EDR_WEBHOOK_SECRET, DATTO_EDR_TOKEN, PORT=3002
4. Start the server: npm start
5. Start ngrok: ngrok http 3002
6. Configure webhook in Datto EDR pointing to your ngrok URL + /webhook/edr

## Roadmap

- [ ] Persistence (SQLite DB + alert history)
- [ ] SENTINEL Dashboard (metrics, alert log, PDF export)
- [ ] Azure deploy for 24/7 operation
- [ ] Multi-tenant support

## Built by

The Launch Box — Internal Security Operations tooling
