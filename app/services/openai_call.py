import aiohttp
from app.core.config import settings

async def azure_openai_call(messages: any, headers) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                settings.AZURE_OPENAI_ENDPOINT,
                headers=headers,
                json={"messages": messages, "max_tokens": 4000}
            ) as response:
                response.raise_for_status()
                response_data = await response.json()
                return response_data["choices"][0]["message"]["content"]
    except aiohttp.ClientError as e:
        raise RuntimeError(f"Error communicating with Azure OpenAI API: {str(e)}")
    except (ValueError, KeyError, IndexError) as e:
        raise RuntimeError(f"Error parsing Azure OpenAI API response: {str(e)}")