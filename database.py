from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite database URL
DATABASE_URL = "sqlite:///./users.db"

# Create the SQLite engine
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Create a SessionLocal for database interaction
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Define the User model (table)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)  # Store hashed passwords
    balance = Column(Integer, default=1000)  # Default balance for new users

# Create the database tables
def init_db():
    Base.metadata.create_all(bind=engine)
