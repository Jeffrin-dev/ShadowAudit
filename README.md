# ShadowAudit

ShadowAudit protects personal data like API keys, emails, 
Aadhaar and PAN numbers from reaching AI chatbots by 
detecting and masking them before they leave your app.

Built for developers building chatbots and AI applications 
that handle personal data.

---

## Why ShadowAudit

Every time a user types into an AI-powered app, sensitive 
data can leak — names, emails, phone numbers, API keys, 
national IDs. ShadowAudit sits between your app and the 
LLM API and stops that from happening.

---

## Quickstart
```bash
pip install shadowaudit
```

Two lines of code. Wrap your existing OpenAI client:
```python
from shadowaudit.sdk.client import ShadowAudit

sa = ShadowAudit.from_config("shadowaudit.yaml")
client = sa.wrap(openai.OpenAI())

# Everything else stays the same
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}]
)
```

---

## What it detects

| Type | Examples |
|---|---|
| PII | Names, emails, phone numbers |
| Indian IDs | Aadhaar, PAN card |
| Global IDs | IBAN, NHS UK number |
| Secrets | OpenAI keys, GitHub tokens, AWS keys, Slack tokens |

---

## Four operating modes

| Mode | What happens |
|---|---|
| `log` | Detect and record. Prompt passes through. Default. |
| `tag` | Detect and label with metadata. |
| `redact` | Replace PII with tokens like `[PERSON_1]`. |
| `block` | Stop the request entirely. |

---

## Policy as code

Drop in a pre-built compliance bundle:
```bash
# HIPAA — blocks all PHI
shadowaudit policy check policies/hipaa.yaml

# PCI-DSS — blocks card data  
shadowaudit policy check policies/pci_dss.yaml

# GDPR — redacts EU personal data
shadowaudit policy check policies/gdpr.yaml
```

Or write your own in YAML:
```yaml
policies:
  - name: block-api-keys
    when:
      detected: [SECRET]
    action: block
```

---

## GDPR Article 30 report
```bash
shadowaudit report --format gdpr --from 2025-06-01 --to 2025-08-31
```

Generates a structured record of processing activities 
automatically from your audit log.

---

## CLI
```bash
shadowaudit scan "My email is john@example.com"
shadowaudit proxy --port 8080 --target https://api.openai.com
shadowaudit policy check policies/gdpr.yaml
shadowaudit report --format gdpr --from DATE --to DATE
```

---

## What ShadowAudit does not protect against

- Vague descriptions with no structured identifiers
- Paraphrased or reconstructed PII in model responses
- Prompt injection attacks
- Adversarial evasion

ShadowAudit is a best-effort detection layer, not a legal 
compliance guarantee. The deploying organization is 
responsible for their own regulatory compliance.

---

## Built with

Python · Microsoft Presidio · detect-secrets · 
spaCy · ChromaDB · FastAPI · Typer

---

## License

MIT
