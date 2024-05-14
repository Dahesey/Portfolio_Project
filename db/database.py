from flask import Flask
from flask_pymongo import PyMongo

def connect_db(app: Flask):
    app = app(__name__)
    app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
    mongo = PyMongo(app)
    return mongo
