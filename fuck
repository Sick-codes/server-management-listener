from fastapi import FastAPI, Request, Depends, Form,  HTTPException
from pydantic import BaseModel
from oauth import Oauth
from asyncio import run as r 
import secrets
from datetime import datetime, timedelta
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from datetime import datetime, timedelta

inst = Oauth()
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter

scopes = [
    'openid',
    'profile',
    'email',
    'phone',
    'library.read',
    'library.append',
    'library.edit',
    'library.write',
    'library.share',
    'admin.users:read',
    'admin.users:invite',
    'admin.users:write'
]


class checkCode(BaseModel):
    client_id: str
    user_code: str


class OauthApp(BaseModel):
    app_id:str
    scopes:list
    



payload = {
        "device_code":secrets.token_urlsafe(5),
        'user_code':secrets.token_urlsafe(9),
        'verify_uri':'http://127.0.0.1:8000/auth/device/verify',
        'pol_uri':'http://127.0.0.1:8000/poll',
        'interval':3
}


@app.post('/token&{client_id}')
@limiter.limit(f"{payload['interval']}/second")
async def get_token(client_id, request: Request):
    is_verified = await inst.searchGrants(str(client_id))
    if is_verified['is_verified']:
        return {
            "bearer":await inst.encode_access_token({
                "user_id":client_id,
                'scopes':await inst.searchGrants(client_id)['scopes'],
                'exp':datetime.utcnow() + timedelta(43)})}
    raise HTTPException(status_code=400, detail='user not verified')



@app.post('/create/app')
async def create_app(request: Request):
    json = await request.json()
    payload['user_code'] = secrets.token_urlsafe(5)
    payload['device_code'] = secrets.token_urlsafe(7)
    await inst.save_data({"device_code":payload['device_code'], **json})
    return payload



@app.post('/auth/device/verify')
async def check_code(json:str = Depends(checkCode)):
    correct_code = await inst.searchGrants(json.client_id)
    if json.user_code == correct_code:
       await inst.update_status(json.client_id)
       return {'success':"user verified"}




