cat > rag_interactive.py << 'EOF'
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma

LLM_MODEL = "qwen2.5:7b"
EMBED_MODEL = "nomic-embed-text"
BASE_URL = "http://localhost:11435"

print("Loading documents and building vector store...\n")

loader = TextLoader("malicious_validation_summary.txt", encoding="utf-8")
docs = loader.load()

text_splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=150)
splits = text_splitter.split_documents(docs)

embeddings = OllamaEmbeddings(model=EMBED_MODEL, base_url=BASE_URL)
vectorstore = Chroma.from_documents(
    documents=splits, 
    embedding=embeddings, 
    persist_directory="./chroma_db"
)

retriever = vectorstore.as_retriever(search_kwargs={"k": 6})
llm = OllamaLLM(model=LLM_MODEL, base_url=BASE_URL, temperature=0.3)

print(" Interactive RAG System Ready!")
print("Type your questions about the validation summary.")
print("Type 'exit' or 'quit' to stop.\n")

while True:
    try:
        query = input("You: ").strip()
        
        if query.lower() in ['exit', 'quit', 'q']:
            print("Goodbye!")
            break
            
        if not query:
            continue

        
        retrieved = retriever.invoke(query)
        context = "\n\n".join([doc.page_content for doc in retrieved])

        prompt = f"""You are a senior IoMT Security SOC Analyst.

Context from validation report:
{context}

User Question: {query}

Provide a clear, professional, and actionable response."""

        response = llm.invoke(prompt)
        print("\nAssistant:\n")
        print(response)
        print("-" * 80 + "\n")

    except KeyboardInterrupt:
        print("\nExiting...")
        break
    except Exception as e:
        print(f"Error: {e}")
EOF
