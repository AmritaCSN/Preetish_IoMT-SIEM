cat > rag_validation.py << 'EOF'
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma

LLM_MODEL = "qwen2.5:7b"
EMBED_MODEL = "nomic-embed-text"
BASE_URL = "http://localhost:11435"

loader = TextLoader("malicious_validation_summary.txt", encoding="utf-8")
docs = loader.load()

text_splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=150)
splits = text_splitter.split_documents(docs)

embeddings = OllamaEmbeddings(model=EMBED_MODEL, base_url=BASE_URL)
vectorstore = Chroma.from_documents(documents=splits, embedding=embeddings, persist_directory="./chroma_db")

retriever = vectorstore.as_retriever(search_kwargs={"k": 5})

llm = OllamaLLM(model=LLM_MODEL, base_url=BASE_URL, temperature=0.3)

print(" RAG System is Ready!\n")

query = "Analyze the validation summary. Explain the poisoning attack and suggest remediation steps for the SOC team."

retrieved = retriever.invoke(query)
context = "\n\n".join([doc.page_content for doc in retrieved])

prompt = f"""You are a senior IoMT Security Analyst specializing in log poisoning attacks.

Context from validation:
{context}

Question: {query}

Provide a precise, technical response including:
1. Clear summary of the poisoning incident with key numbers.
2. Specific reasons why the 14,781 logs bypassed Wazuh (mention possible evasion techniques like Label Flipping, Timestamp Jitter, etc.).
3. Prioritized remediation steps tailored for SOC team, including immediate actions on MinIO and Wazuh.
4. Any recommendations for improving detection in future.

Be concise, technical, and actionable."""
response = llm.invoke(prompt)
print(response)
EOF
