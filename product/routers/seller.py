from fastapi import APIRouter
from ..import schemas, models
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.params import Depends
from ..database import get_db


router = APIRouter(
    tags=["Sellers"],
    prefix="/seller"
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post('/', response_model=schemas.DisplaySeller)
def create_seller(request: schemas.Seller, db: Session = Depends(get_db)):
    hashedpassword = pwd_context.hash(request.password)
    new_seller = models.Seller(username=request.username, 
                               email=request.email, 
                               password=hashedpassword)
    db.add(new_seller)
    db.commit()
    db.refresh(new_seller)
    return new_seller