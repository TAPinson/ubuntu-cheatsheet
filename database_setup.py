from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=True)
    picture = Column(String(250), nullable=True)


class Category(Base):
    __tablename__ = 'Category'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }

class Application(Base):
    __tablename__ = 'Application'
    name = Column(String(80), nullable=False)
    id = Column(Integer, autoincrement=True, primary_key=True)
    description = Column(String(250))
    repository = Column(String(250))
    aptget = Column(String(250))
    category = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
	        'repository': self.repository,
	        'aptget': self.aptget,
            'id': self.id,
            'category': self.category,
        }


engine = create_engine('sqlite:///ubuntuapps.db')


Base.metadata.create_all(engine)
