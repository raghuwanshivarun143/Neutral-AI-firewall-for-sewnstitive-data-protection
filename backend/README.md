\# CIPHER01 — AI Firewall for Sensitive Data Protection



\## Problem Statement

AI applications (ChatGPT, Claude, Groq) are used everywhere, but they have no security layer. Employees accidentally leak API keys, emails, SSNs, and passwords to AI providers. Malicious users perform prompt injection and jailbreak attacks. There is no centralized way to inspect AI traffic before it reaches the provider.



\## Solution

CIPHER01 is an AI Firewall that sits between your application and AI providers. It:

\- Scans inbound requests for PII, API keys, and prompt injections

\- Assigns risk scores (LOW, MEDIUM, HIGH, CRITICAL)

\- Applies policies: ALLOW, MASK, or BLOCK

\- Scans outbound AI responses for data leaks and canary tokens

\- Logs all activity for audit



\## Architecture

Application → CIPHER01 Firewall → AI Provider (OpenAI/Groq/Ollama)

↓

Inbound Scan → Risk → Policy → Route → Outbound Scan



text



\## Tech Stack

\- \*\*Backend:\*\* Python, FastAPI, SQLAlchemy, SQLite

\- \*\*Frontend:\*\* Next.js 16, React 19, Tailwind CSS 4, Framer Motion

\- \*\*Providers:\*\* OpenAI, Groq, Ollama



\## Features

\- Real-time dashboard with live metrics

\- Multi-provider routing (OpenAI, Groq, Ollama)

\- PII detection (email, phone, SSN)

\- API key detection (OpenAI, AWS)

\- Prompt injection detection

\- Policy management

\- Red Team Labs (attack simulation)

\- Evaluation Lab (test suite)



\## Setup

\### Backend

```bash

cd backend

python -m venv .venv

.venv\\Scripts\\activate

pip install -r requirements.txt

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

Frontend

bash

cd frontend

npm install

npm run dev

Environment Variables

Create .env in backend/:



text

GROQ\_API\_KEY=your\_key\_here

DEFAULT\_PROVIDER=groq

DEFAULT\_MODEL=openai/gpt-oss-20b

API Endpoints

POST /v1/chat/completions — Main firewall endpoint



GET /api/analytics — Dashboard metrics



GET /api/requests — Request history



POST /api/scan/text — Manual scan



GET /health — System health



Author

Varun Raghuwanshi



License

MIT



text



\*\*Save kar\*\* (Ctrl+S) aur Notepad band kar.



Phir yeh 3 commands chala:



```powershell

git add README.md

git commit -m "Add professional README with architecture and setup"

git push

Bhai, output bhej! 🏃‍♂️💨

