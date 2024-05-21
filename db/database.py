from pymongo import MongoClient

def get_db():
    try:
        client = MongoClient('cluster0.bqpfelu.mongodb.net', 27017, username='dahesey', password='QvL3T3Sv5hVIOueu')
        db = client["portfolio_project"]
        print("connection successful...")
        return db
    except Exception as e:
        print(str(e))
        raise str(e)
