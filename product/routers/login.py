from fastapi import APIRouter, Depends, status, HTTPException
from ..import models
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.params import Depends
from ..database import get_db
from ..schemas import TokenData
from datetime import datetime, timedelta
from jose import jwt,JWTError
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.oauth2 import OAuth2PasswordRequestForm

SECRET_KEY = '0f32ff829cf205815676071167749b6fe1e3f58fda89488f359dedb3e36d2d8f'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60

router = APIRouter(
    tags= ['Login'],
    prefix = '/login'
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')


def generate_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

@router.post('/')
def login(request: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):

    seller = db.query(models.Seller).filter(
        models.Seller.username == request.username).first()
    if not seller:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail= 'username not found or invalid user')
    if not pwd_context.verify(request.password, seller.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Invalid password')
    
    access_token = generate_token(
        data={"sub":seller.username}
    )
    return {"access_token":access_token, "token_type":"bearer"}

def get_current_user(token:str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid auth credentials",
        headers={'WWW-Authenticate':'Bearer'},
    )
    
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username:str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception