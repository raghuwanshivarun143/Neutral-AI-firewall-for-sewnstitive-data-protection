# CIPHER01 — AI Firewall for Sensitive Data Protection

## Overview
CIPHER01 is an AI firewall designed to inspect requests before they reach an AI provider. It detects sensitive information and malicious instructions, applies security policies, and inspects AI responses before returning them to users.

## Problem Statement
AI applications such as ChatGPT, Claude, and Groq are widely used but lack a centralized security layer. This creates several risks:
- Sensitive data such as API keys, emails, and government identifiers may be transmitted to external providers unintentionally.
- Malicious users may attempt prompt injection or jailbreak attacks to bypass AI safety controls.
- Organizations lack an audit trail for AI usage and data exposure.
- Regulatory frameworks such as GDPR, HIPAA, and SOC2 require protection of personally identifiable information.

No existing solution provides an inline firewall that inspects AI traffic before it reaches the provider.

## Solution
CIPHER01 functions as a security gateway between an application and AI providers. It performs the following operations:
1. Scans inbound requests for personally identifiable information, API keys, and prompt injection attempts.
2. Assigns a risk score on a scale from 0.0 to 10.0.
3. Applies a policy decision: ALLOW, MASK, or BLOCK.
4. Routes the request to a configured AI provider.
5. Scans the outbound AI response for data leaks, canary tokens, and suspicious URLs.
6. Applies response masking or blocking based on policy.
7. Logs all activity to a database for auditing and compliance.

## Architecture
The request pipeline is as follows:

Incoming request → input scanning → sensitive data detection → risk assessment → policy decision → input sanitization or blocking → AI provider routing → outbound response scanning → response masking or blocking → logging and database persistence → API response.

Supported AI providers include OpenAI, Groq, and Ollama.

## Technology Stack
Backend:
- Python 3.11 or higher
- FastAPI
- Uvicorn
- SQLAlchemy
- SQLite
- HTTPX
- Pydantic Settings

Frontend:
- Next.js 16 with App Router
- React 19
- Tailwind CSS 4
- Framer Motion
- Recharts
- Lucide React

AI Providers:
- OpenAI (for example, gpt-4o-mini)
- Groq (for example, openai/gpt-oss-20b)
- Ollama (for example, llama3.2:3b, local inference)

## Features
Detection:
- Personally identifiable information detection, including email addresses, phone numbers, and Social Security Numbers.
- Secret detection, including OpenAI keys, AWS keys, and generic API keys.
- Prompt injection detection, including instructions to ignore previous context or reveal the system prompt.
- Encoding detection, including Base64, URL encoding, and hexadecimal.
- Canary token detection.

Enforcement:
- Risk scoring on a scale from 0.0 to 10.0.
- Policy engine with ALLOW, MASK, and BLOCK actions.
- Inbound sanitization to mask sensitive data before transmission.
- Outbound sanitization to mask sensitive data in responses.
- Provider routing across multiple AI backends.

Monitoring:
- Real-time dashboard with live metrics.
- Traffic volume chart showing allowed, masked, and blocked requests.
- Provider health status.
- Recent security events.
- Request history and audit log.

Testing:
- Red Team Labs for attack simulation.
- Evaluation Lab for automated test suites.
- Request Scanner interface for manual scanning.

## Setup and Installation
Prerequisites:
- Python 3.11 or higher
- Node.js 18 or higher
- Git

Backend setup:
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
