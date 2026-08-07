import asyncio
from langchain_openai import ChatOpenAI
from guardian.llm.config import LLMConfig
async def main():
    c = LLMConfig.from_env()
    llm = ChatOpenAI(base_url=c.base_url, api_key=c.api_key, model=c.model, temperature=1.0)
    print("Invoking...")
    res = await llm.ainvoke("hello")
    print(res.content)
asyncio.run(main())
