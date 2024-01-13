from fastapi import FastAPI, File, UploadFile
from typing import Annotated
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dbHandler import *

class User(BaseModel):
    _id: str | None = None
    username: str | None = None
    email: str | None = None
    password: str | None = None
    tag: list | None = None
    bio: str | None = None
    pfp: str | None = None
    city: str | None = None
    gender: str | None = None
    birthday: str | None = None

class AuthInfo(BaseModel):
    username: str
    password: str

app = FastAPI()
@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/user/{id}")
async def getUserAPI(id):
    return getUser(id)

@app.post("/user/update/")
async def updateUserAPI(user: User):
    return updateUser(user.model_dump())

@app.post("/user/new/")
async def newUserAPI(user: User):
    return newUser(user.model_dump())

@app.get("/user/list/")
async def listUserAPI():
    return listUser()

@app.post("/user/authenticate/")
async def authenticateAPI(authInfo: AuthInfo):
    return authenticate(username = authInfo.username, psw = authInfo.password)


# FILES
@app.post("/upload/cv/")
async def uploadCV(file: UploadFile):
    try:
        fileID = await saveFile(file)
    except Exception as e:
        print(e)
        return {"message": "Unable to upload"}, 400
    return {"message": f"Uploaded successfully {file.filename}", "fileID":str(fileID)}

@app.get("/asset/{id}", )
async def getAssetAPI(id):
    dict = await getAsset(id)
    if "path" in dict:
        return FileResponse(dict["path"], media_type='application/octet-stream', filename=dict["filename"])
    else:
        return dict["filename"]
