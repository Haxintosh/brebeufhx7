import base64
import hashlib
from pymongo import MongoClient
import gridfs
import uuid
import bcrypt
from dotenv import dotenv_values

# Load environment variables
env = dotenv_values(".env")
mongoDBUrl = env["USERDBURL"]
gridFSUrl = env["GRIDFSDBURL"]

# Connect to MongoDB and GridFS
userDB = MongoClient(mongoDBUrl)['userDB']
gridFSDB = MongoClient(gridFSUrl)["uploadDB"]
fs = gridfs.GridFS(gridFSDB)

def newUser(dict):
    userCollection = userDB["user"]
    user = {
        "_id": str(uuid.uuid4()),
        "username": dict.get("username"),
        "email": dict.get("email"),
        "password": hashPsw(dict.get("password")),
        "tag": dict.get("tag"),
        "bio": dict.get("bio"),
        "pfp": dict.get("pfp"),
        "city": dict.get("city"),
        "gender": dict.get("gender"),
        "birthday": dict.get("birthday"),
    }
    userCollection.insert_one(user)
    del user["password"]
    return user

def getUser(id):
    userCollection = userDB["user"]
    return userCollection.find_one({"_id": id})

def getDB():
    CONNECTION_STRING = mongoDBUrl
    client = MongoClient(CONNECTION_STRING)
    return client['userDB']

def getGridFSDB():
    CONNECTION_STRING = gridFSUrl
    gridFSDB = MongoClient(CONNECTION_STRING)["uploadDB"]
    return gridFSDB

def listUser():
    userList = []
    userCollection = userDB["user"]
    cursor = userCollection.find()
    for i in cursor:
        userList.append(i)
    return userList

def updateUser(dict):
    userCollection = userDB["user"]
    updateDict = {}

    for key, value in dict.items():
        if value is not None:
            updateDict.update({key: value})

    if updateDict:
        userCollection.update_one(filter={"_id": dict["_id"]}, update={"$set": updateDict})
        return True
    else:
        return None

def authenticate(username, psw):
    userCollection = userDB["user"]
    id = idFromUser(username)
    document = userCollection.find_one({"_id": id})

    if document:
        if verifyPsw(hashed=document["password"], psw=psw):
            return {"sessionID": str(uuid.uuid4()), "userID":str(userCollection.find_one({"_id": id}))}
        else:
            return "Wrong password"
    else:
        return "Document does not exist/"

def idFromUser(username):
    userCollection = userDB["user"]
    document = userCollection.find_one({"username": username})
    if document:
        return document["_id"]
    else:
        return None

async def saveFile(file): # add redundant uploading check 
    metadataCollection = gridFSDB["metadata"]
    content = await file.read()
    encoded = base64.b64encode(content)
    fileHash = md5Hash(content)
    returnID = str(uuid.uuid4())
    id = fs.put(encoded, filename=file.filename)
    metadata = {
        "filename": file.filename,
        "hash": fileHash,
        "file_id": id,
        "uuid": returnID
    }
    metadataCollection.insert_one(metadata)
    return returnID

async def getAsset(id):
    metadataCollection = gridFSDB["metadata"]
    objectid = metadataCollection.find_one({"uuid": id})
    if objectid:
        object = metadataCollection.find_one({"uuid": id})["file_id"]
        print(type(object))
        asset = fs.find_one({'_id': object}).read()
        decodedAsset = base64.b64decode(asset)
        path = f"uploads/{metadataCollection.find_one({'uuid': id})['filename']}"
        f = open(path, "wb")
        f.write(decodedAsset)
        return {"path": path, "filename":str({metadataCollection.find_one({'uuid': id})['filename']})}
    else:
        return {"message": "No file"}

# helpers
def hashPsw(psw):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(psw.encode('utf-8'), salt)
    return hashed

def verifyPsw(hashed, psw):
    return bcrypt.checkpw(psw.encode('utf-8'), hashed)

def md5Hash(content):
    md5 = hashlib.md5()
    md5.update(content)
    return md5.hexdigest()
