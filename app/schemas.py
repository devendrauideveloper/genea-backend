from pydantic import BaseModel, EmailStr, Field, ConfigDict, model_validator # type: ignore
from typing import Optional, Literal

class UserBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = Field(min_length=1, max_length=100)
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(min_length=6, max_length=128)

class UserLogin(BaseModel):
    model_config = ConfigDict(extra="ignore")
    # Accept any one of these as the identifier
    identifier: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: str

    @model_validator(mode="after")
    def _must_have_one_identifier(self):
        if not (self.identifier or self.username or self.email):
            raise ValueError("Provide identifier OR username OR email")
        return self

class UserPublic(BaseModel):
    id: int
    name: str
    username: str
    email: EmailStr


class CustomerBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = Field(min_length=1, max_length=100)
    auth_method: Literal["credentials", "token"]
    username: Optional[str] = None  # required only when credentials

class CustomerCreate(CustomerBase):
    # password when credentials, or token when token
    secret: str = Field(min_length=1, max_length=512)
    # external UUID provided by UI (UI will not send this anymore; server will generate)
    customer_uuid: Optional[str] = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def _validate_by_method(self):
        if self.auth_method == "credentials" and not self.username:
            raise ValueError("username is required when auth_method is 'credentials'")
        return self

class CustomerPublic(BaseModel):
    id: int
    name: str
    auth_method: str
    username: Optional[str] = None
    customer_uuid: Optional[str] = None
