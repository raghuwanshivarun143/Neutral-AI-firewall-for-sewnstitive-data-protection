from app.providers.openai import OpenAIProvider
import os

class GroqProvider(OpenAIProvider):
    def __init__(self):
        super().__init__(
            name="groq",
            base_url="https://api.groq.com/openai/v1",
            api_key=os.getenv("GROQ_API_KEY")
        )