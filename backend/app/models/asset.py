from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base
from sqlalchemy.orm import relationship

class Asset(Base):

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False)
    vendor = Column(String, nullable=False)
    model = Column(String, nullable=False)
    department = Column(String, nullable=False)
    os_family = Column(String, nullable=False)
    version = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    h_cpe = Column(String, nullable=False)
    risk_level = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    cve_relations = relationship(
        "AssetCVERelation",
        back_populates="asset",
        cascade="all, delete-orphan",
        passive_deletes=True
    )