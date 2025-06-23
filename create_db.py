import logging
import os
from datetime import datetime

from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cấu hình SQLAlchemy và mã hóa mật khẩu
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
instance_dir = os.path.join(BASE_DIR, 'instance')
os.makedirs(instance_dir, exist_ok=True)
db_path = os.path.join(instance_dir, 'secure_file_transferr.db')
db_uri = f'sqlite:///{db_path}'
engine = create_engine(db_uri, echo=False)
Session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Mô hình User
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)


# Mô hình TransferLog
class TransferLog(Base):
    __tablename__ = "transfer_logs"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), index=True)
    receiver_id = Column(Integer, ForeignKey("users.id"), index=True)
    file_name = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String)
    subject = Column(String, nullable=True)
    message = Column(String, nullable=True)
    cloud_link = Column(String, nullable=True)
    file_id = Column(String, nullable=True)


def initialize_database():
    # Xóa database cũ nếu có
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            logger.info(f"Deleted existing database: {db_path}")
        except Exception as e:
            logger.error(f"Error deleting database: {str(e)}")
            return False

    try:
        Base.metadata.create_all(engine)
        logger.info("Created tables: 'users' and 'transfer_logs'")

        session = Session()

        # Thêm user mẫu
        sample_user = User(
            username="user1",
            hashed_password=pwd_context.hash("pass123"),
            email="user1@example.com"
        )
        session.add(sample_user)
        session.commit()
        session.close()
        logger.info("Added sample user: user1")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False


if __name__ == "__main__":
    if initialize_database():
        logger.info("Database initialization completed successfully.")
    else:
        logger.error("Database initialization failed.")
