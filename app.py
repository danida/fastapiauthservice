from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from pydantic import BaseModel
import jwt

SQLALCHEMY_DB_URL = "mysql://admin:admin@localhost/authservice"
engine = create_engine(
    SQLALCHEMY_DB_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
JWT_SECRET = 'fuckingsecure'
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(16))
    fullname = Column(String(16))
    nickname = Column(String(16))
    passwd_hash = Column(String(255))

    @classmethod
    async def get_user(cls, username):
        return SessionLocal().query(User).filter_by(username=username).first()

    def verify_password(self, password):
        return SessionLocal().query(User).filter_by(username = self.username, passwd_hash=password).first()


class UserCreate(BaseModel):
    username: str
    fullname: str
    nickname: str
    passwd_hash: str


def create_user(db: Session, user: UserCreate):
    fake_hashed_password = user.passwd_hash + "notreallyhashed"
    db_user = User(username=user.username, fullname=user.fullname, nickname=user.nickname,
                   passwd_hash=fake_hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


Base.metadata.create_all(bind=engine)
app = FastAPI()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def authenticate_user(username: str, password: str):
    user = await User.get_user(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get_user(username=payload.get('username'))
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    return user

@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        return {'error': 'invalid credentials'}

    user_obj = await User.get_user(form_data.username)
    token = jwt.encode({'username':user_obj.username, 'nickname':user_obj.nickname}, JWT_SECRET)

    return {'access_token': token, 'token_type': 'bearer'}

@app.get ("/users/me")
def get_me(user: UserCreate = Depends(get_current_user)):
    return {'username':user.username}

@app.post("/user/create", response_model=UserCreate)
def create_user_post(user: UserCreate, db: Session = Depends(get_db)):
    create_user(db=db, user=user)
