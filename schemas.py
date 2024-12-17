from pydantic import BaseModel

# Schema for user registration
class UserCreate(BaseModel):
    username: str
    password: str

# Schema for user login
class UserLogin(BaseModel):
    username: str
    password: str

# Schema for user response (to exclude sensitive data)
class UserResponse(BaseModel):
    id: int
    username: str
    balance: int

    class Config:
        orm_mode = True
