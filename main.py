from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import init_db, SessionLocal, User
from schemas import UserCreate, UserLogin, UserResponse
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Initialize the app
app = FastAPI()

# Initialize the database
init_db()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT secret key and algorithm
SECRET_KEY = "your_jwt_secret_key"
ALGORITHM = "HS256"

# Function to hash a password
def hash_password(password: str):
    return pwd_context.hash(password)

# Function to verify a password
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Function to create a JWT token
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=30)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Route: Register a new user
@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed_password = hash_password(user.password)
    new_user = User(username=user.username, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

# Route: Login and get JWT token
@app.post("/login")
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Create a JWT token
    access_token = create_access_token(data={"sub": db_user.username})
    return {"access_token": access_token, "token_type": "bearer", "balance": db_user.balance}

# Route: Get user details (protected route)
@app.get("/me", response_model=UserResponse)
def get_user_details(db: Session = Depends(get_db), token: str = Depends(lambda: "fake-token")):
    return {"message": "Example of JWT-protected endpoint"}
