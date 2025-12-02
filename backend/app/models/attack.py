from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base
from sqlalchemy.orm import relationship

class Attack(Base):

    __tablename__ = "attacks"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, unique=True, nullable=False, index=True)
    external_id = Column(String, nullable=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    platforms = Column(String, nullable=True)
    tactics = Column(Text, nullable=True)
    data_sources = Column(String, nullable=True)
    detection = Column(String, nullable=True)
    permissions_required = Column(String, nullable=True)
    url = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    capec_relations = relationship(
        "CAPECAttackRelation",
        back_populates="attack",
        cascade="all, delete-orphan",
        passive_deletes=True
    )