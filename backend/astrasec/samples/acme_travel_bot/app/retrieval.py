import chromadb

db = chromadb.PersistentClient(path="./bookings")


def search_bookings(q: str) -> str:
    col = db.get_or_create_collection("bookings")
    res = col.query(query_texts=[q], n_results=3)
    return "\n".join(res["documents"][0])
