import httpx

client = httpx.Client(timeout=15)
r = client.post(
    'http://localhost:8000/api/scan/text',
    json={'text': 'test@example.com', 'include_injection': True, 'include_encoding': True}
)
print('Status:', r.status_code)
print('Body:', r.text[:2000])
