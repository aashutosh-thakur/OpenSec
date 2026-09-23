from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

# SQLite local DB for development
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./opensecx.db"

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL, 
    echo=True, 
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
