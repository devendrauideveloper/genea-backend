# app/main.py
from typing import List, Optional, Literal

import httpx
import uuid
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    Query,
    Response,
    Path,
    Header,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import Base, engine, get_db
from app import crud
import json
from app.schemas import (
    UserCreate,
    UserLogin,
    UserPublic,
    CustomerCreate,
    CustomerPublic,
    DraftSave,
    DraftPublic,
)
from app.security import verify_password
from fastapi import Body





def _too_long(p: str | None) -> bool:
    if not p:
        return True
    try:
        return len(p.encode("utf-8")) > 72
    except Exception:
        return True

# --------------------------------------------------------------------------------------
# App setup
# --------------------------------------------------------------------------------------

settings = get_settings()

# Create tables on startup (for demos). In production use migrations.
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Auth API (FastAPI + MySQL)", debug=settings.DEBUG)
origins = [
    "http://kpax.us-east-2.elasticbeanstalk.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,  # must be False with "*"
    expose_headers=["*"],
    max_age=86400,
)
# --------------------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "env": settings.ENV}

# --------------------------------------------------------------------------------------
# TEMP auth dependency (replace with JWT/session later)
# --------------------------------------------------------------------------------------

def get_current_user(
    db: Session = Depends(get_db),
    x_user_id: int = Header(..., alias="X-User-Id"),
) -> dict:
    """
    Minimal stand-in for auth.
    Returns {"id": <int>} if the user exists, else 401.
    """
    user = crud.get_user(db, x_user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    return {"id": user.id}

# --------------------------------------------------------------------------------------
# Auth (register / login)
# --------------------------------------------------------------------------------------

@app.post("/api/v1/auth/register", response_model=UserPublic, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    # Prevent duplicates
    
    if crud.get_user_by_username(db, payload.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    if crud.get_user_by_email(db, payload.email):
        raise HTTPException(status_code=409, detail="Email already exists")
    if _too_long(payload.password):
        raise HTTPException(status_code=400, detail="Password too long (max 72 bytes)")


    try:
        user = crud.create_user(
            db,
            name=payload.name,
            username=payload.username,
            email=payload.email,
            password=payload.password,
        )
        return UserPublic.model_validate(user.__dict__)
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Username or email already exists")
    

@app.post("/api/v1/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    ident = (payload.identifier or payload.username or "").strip()
    email = (payload.email or "").strip().lower()

    if not ident and not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide username or email",
        )

    # 1) Fetch user first
    user = (
        crud.get_user_by_username(db, ident)
        or crud.get_user_by_email(db, ident.lower())
        if ident
        else crud.get_user_by_email(db, email)
    )

    # 2) Optional: reject impossible bcrypt lengths early
    if _too_long(payload.password):
        # choose 400 if you prefer; 401 keeps it opaque
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 3) Verify password (and never throw)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "message": "Login successful",
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
        },
    }

# @app.post("/api/v1/auth/login")
# def login(payload: UserLogin, db: Session = Depends(get_db)):
    ident = (payload.identifier or payload.username or "").strip()
    email = (payload.email or "").strip().lower()

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user = None
    if ident:
        user = crud.get_user_by_username(db, ident) or crud.get_user_by_email(db, ident.lower())
    elif email:
        user = crud.get_user_by_email(db, email)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide username or email",
        )
    
    if _too_long(payload.password):
    # Avoid 500; make it an auth failure (or 400 if you prefer)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return {
        "message": "Login successful",
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
        },
    }

# --------------------------------------------------------------------------------------
# Users (test helpers)
# --------------------------------------------------------------------------------------

@app.get("/api/v1/users", response_model=list[UserPublic])
def get_users(db: Session = Depends(get_db)):
    users = crud.get_users(db)
    return [UserPublic.model_validate(u.__dict__) for u in users]

@app.get("/api/v1/users/{user_id}", response_model=UserPublic)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = crud.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserPublic.model_validate(user.__dict__)

# --------------------------------------------------------------------------------------
# Customers (creator-only ownership)
# --------------------------------------------------------------------------------------

@app.post("/api/v1/customers", response_model=CustomerPublic, status_code=201)
def create_customer_api(
    payload: CustomerCreate,
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    if crud.get_customer_by_name(db, payload.name):
        raise HTTPException(status_code=409, detail="Customer name already exists")
    # If the customer uses the Sequr token auth method, verify the API key
    if payload.auth_method == "token":
        verify_url = "https://api.sequr.io/v2/api_key/verify"
        headers = {
            "Authorization": f"Bearer {payload.secret}",
            "Content-Type": "application/json",
        }
        request_body = {"api_key": payload.secret}
        print(f"=== SEQUR API VERIFICATION REQUEST ===")
        print(f"URL: {verify_url}")
        print(f"Headers: {headers}")
        print(f"Body: {request_body}")
        try:
            resp = httpx.post(verify_url, json=request_body, headers=headers, timeout=10.0)
            print(f"=== SEQUR API RESPONSE ===")
            print(f"Status Code: {resp.status_code}")
            print(f"Response Headers: {dict(resp.headers)}")
            print(f"Response Body: {resp.text}")
        except httpx.RequestError as e:
            print(f"Error contacting Sequr API: {e}")
            raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e

        # Treat non-200 as verification failure
        if resp.status_code != 200:
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            raise HTTPException(status_code=resp.status_code, detail=body)

        # If Sequr returns an explicit validity flag, ensure it's truthy
        try:
            body = resp.json()
            if isinstance(body, dict) and ("valid" in body) and not body.get("valid"):
                raise HTTPException(status_code=400, detail=body)
        except ValueError:
            # non-json body — continue because status_code was 200
            pass

    # Generate a customer_uuid server-side (UI no longer sends this)
    generated_customer_uuid = str(uuid.uuid4())

    customer = crud.create_customer(
        db,
        name=payload.name,
        auth_method=payload.auth_method,
        username=payload.username,
        secret_plain=payload.secret,  # raw token/password now (do not hash)
        customer_uuid=generated_customer_uuid,
        created_by_user_id=current["id"],
    )
    return CustomerPublic.model_validate(customer, from_attributes=True)

@app.get("/api/v1/customers", response_model=list[CustomerPublic])
def list_customers(
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    customers = crud.get_customers(
        db, created_by_user_id=current["id"], skip=skip, limit=limit
    )
    return [CustomerPublic.model_validate(c, from_attributes=True) for c in customers]

@app.get("/api/v1/customers/{customer_id}", response_model=CustomerPublic)
def get_customer_api(
    customer_id: int,
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if customer.created_by_user_id != current["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    return CustomerPublic.model_validate(customer, from_attributes=True)

class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    auth_method: Optional[Literal["credentials", "token"]] = None
    username: Optional[str] = None
    secret: Optional[str] = Field(default=None, min_length=1, max_length=512)
    customer_uuid: Optional[str] = Field(default=None, min_length=1, max_length=255)

@app.put("/api/v1/customers/{customer_id}", response_model=CustomerPublic)
def update_customer_api(
    customer_id: int,
    payload: CustomerUpdate,
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if customer.created_by_user_id != current["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")

    updated = crud.update_customer(
        db,
        customer_id,
        name=payload.name,
        auth_method=payload.auth_method,
        username=payload.username,
        secret_plain=payload.secret,  # raw token/password now
        customer_uuid=payload.customer_uuid,
    )
    return CustomerPublic.model_validate(updated, from_attributes=True)

@app.delete("/api/v1/customers/{customer_id}", status_code=204)
def delete_customer_api(
    customer_id: int,
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if customer.created_by_user_id != current["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")

    try:
        ok = crud.delete_customer(db, customer_id)
    except IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Customer cannot be deleted due to existing references",
        )

    if not ok:
        raise HTTPException(status_code=404, detail="Customer not found")

    return Response(status_code=204)

# --------------------------------------------------------------------------------------
# Drafts (Access Control Grid Drafts)
# --------------------------------------------------------------------------------------

def _draft_to_public(obj) -> DraftPublic:
    try:
        rows = json.loads(obj.grid_json or "[]")
    except Exception:
        rows = []
    return DraftPublic(
        id=obj.id,
        user_id=obj.user_id,
        customer_id=obj.customer_id,
        location_uuid=obj.location_uuid,
        controllers=obj.controllers,
        downstreams=obj.downstreams,
        grid_rows=rows,
    )


@app.get("/api/v1/customers/{customer_id}/draft", response_model=DraftPublic | None)
def get_draft_api(
    customer_id: int,
    location_uuid: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    draft = crud.get_draft(
        db,
        user_id=current["id"],
        customer_id=customer_id,
        location_uuid=location_uuid,
    )
    if not draft:
        return None
    return _draft_to_public(draft)


@app.put("/api/v1/customers/{customer_id}/draft", response_model=DraftPublic)
def save_draft_api(
    customer_id: int,
    payload: DraftSave,
    location_uuid: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    draft = crud.upsert_draft(
        db,
        user_id=current["id"],
        customer_id=customer_id,
        location_uuid=location_uuid,
        controllers=payload.controllers,
        downstreams=payload.downstreams,
        grid_rows=payload.grid_rows,
    )
    return _draft_to_public(draft)


@app.delete("/api/v1/customers/{customer_id}/draft", status_code=204)
def delete_draft_api(
    customer_id: int,
    location_uuid: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    crud.delete_draft(
        db,
        user_id=current["id"],
        customer_id=customer_id,
        location_uuid=location_uuid,
    )
    return Response(status_code=204)

# --------------------------------------------------------------------------------------
# Wrapper endpoint: call Sequr with token from DB (raw value now)
# --------------------------------------------------------------------------------------

@app.get("/api/v1/customers/{customer_id}/sequr/locations")
async def sequr_locations_proxy(
    customer_id: int = Path(..., ge=1),
    uuid: str = Query(..., min_length=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current=Depends(get_current_user),
):
    customer = crud.get_customer(db, customer_id)
    print("======= customer token ======", customer.secret_hash)
    if not customer:
        print("======= customer not found ======")
        raise HTTPException(status_code=404, detail="Customer not found")
    if customer.created_by_user_id != current["id"]:
        print("======= not allowed ======")
        raise HTTPException(status_code=403, detail="Not allowed")

    token = crud.get_customer_token(db, customer_id)
    print("======= token ======", token)
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")
    print("======= token after check ======", token)

    # If Sequr expects "Bearer <token>", change to: f"Bearer {token}"
    headers = {
        "Authorization": "Bearer "+token,
        "Accept": "application/json",
    }

    url = f"https://api.sequr.io/v2/customer/{uuid}/location"
    params = {"page": page, "page_size": page_size}

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers, params=params)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e

    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )
class ReaderModel(BaseModel):
    value: str
    label: str
    default: bool  # Add this if present in some responses

@app.get(
    "/api/v1/customers/{customer_id}/sequr/reader-models",
    name="get reader model",
    response_model=List[ReaderModel]
)
async def get_reader_model(
    customer_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    url = "https://api.sequr.io/v2/controller_model"

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e

    # Always forward the upstream response to the client (body, status, and content-type)
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )

class ControllerCreateRequest(BaseModel):
    location_uuid: str
    timezone: str
    description: Optional[str] = ""
    model: str
    mac: str
    name: str

class ControllerResponseMeta(BaseModel):
    message: str

class ControllerResponseData(BaseModel):
    uuid: str
    scp_number: int
    name: str
    description: Optional[str]
    mac: str
    vendor: str
    model: str
    service_type: str
    timezone: str
    is_online: bool
    last_online_at: Optional[str]
    last_offline_at: Optional[str]
    firmware_version: Optional[str]
    firmware_date: Optional[str]
    serial_number: Optional[str]
    is_battery_failure: bool
    is_power_failure: bool
    is_tampered: bool
    notes: Optional[str]
    db_size: int
    network_settings: Optional[dict]
    host_communication_primary_settings: Optional[dict]
    host_communication_alternate_settings: Optional[dict]
    reboot_status: str
    is_details_verified: bool
    is_hw_resync_available: bool
    is_key_resync_available: bool
    last_resync_status: Optional[str]
    last_resync_started_at: Optional[str]
    location_uuid: str
    customer_uuid: str
    created_at: str
    updated_at: str
    is_new_1105_command: bool
    floor_offset: int
    floor_flags: int
    replacement_details: dict

class ControllerCreateResponse(BaseModel):
    meta: ControllerResponseMeta
    data: ControllerResponseData

@app.post(
    "/api/v1/customers/{customer_id}/sequr/controllers",
    name="create controller",
    response_model=ControllerCreateResponse
)
async def create_controller(
    customer_id: int = Path(..., ge=1),
    uuid: str = Query(..., min_length=1),
    payload: ControllerCreateRequest = Body(...),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    url = f"https://mercury-ac-api.sequr.io/v1/customer/{uuid}/controller"

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.post(url, headers=headers, json=payload.dict())
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    # Forward upstream response (success or error) to the caller
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )

class InterfaceModel(BaseModel):
    value: str
    label: str
    type: str
    default: bool
    interface_panel_port: str
    manufacturer: str

@app.get(
    "/api/v1/customers/{customer_id}/sequr/interface-models",
    response_model=List[InterfaceModel],
    name="get interface models"
)
async def get_interface_models(
    customer_id: int = Path(..., ge=1),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    url = "https://mercury-ac-api.sequr.io/static/interface_models.json"

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    # Forward upstream response (success or error) to the caller
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )

class MSP1PortController(BaseModel):
    uuid: str
    scp_number: int
    name: str
    mac: str
    model: str
    timezone: str
    is_online: bool

class MSP1PortData(BaseModel):
    uuid: str
    name: str
    msp1_number: int
    port_number: int
    baud_rate: int
    reply_time: int
    n_protocol: str
    n_dialect: int
    type: str
    controller: MSP1PortController
    created_at: str
    updated_at: str
    controller_uuid: str
    location_uuid: str
    customer_uuid: str

class MSP1PortMeta(BaseModel):
    message: str

class MSP1PortResponse(BaseModel):
    meta: MSP1PortMeta
    data: List[MSP1PortData]


@app.get(
    "/api/v1/customers/{customer_id}/sequr/msp1-port",
    response_model=MSP1PortResponse,
    name="get msp1 port"
)
async def get_msp1_port(
    customer_id: int = Path(..., ge=1),
    customer_uuid: str = Query(..., min_length=1),
    location_uuid: str = Query(..., min_length=1),
    controller_uuid: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    url = (
        f"https://mercury-ac-api.sequr.io/v1/customer/{customer_uuid}/msp1_port"
        f"?location_uuid={location_uuid}&controller_uuid={controller_uuid}"
    )

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    # Forward upstream response (success or error) to the caller
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )

class InterfacePanelRequest(BaseModel):
    location_uuid: str
    name: str
    description: Optional[str] = ""
    model: str
    address: int
    msp1_port_uuid: str
    manufacturer: str

class InterfacePanelMeta(BaseModel):
    message: str

class InterfacePanelMSP1Port(BaseModel):
    uuid: str
    name: str
    msp1_number: int
    port_number: int
    baud_rate: int
    reply_time: int
    n_protocol: str
    type: str

class InterfacePanelController(BaseModel):
    uuid: str
    scp_number: int
    name: str
    mac: str
    model: str
    timezone: str
    is_online: bool
    created_at: Optional[str]
    updated_at: Optional[str]

class InterfacePanelData(BaseModel):
    uuid: str
    sio_number: int
    ip_address: Optional[str]
    hostname: Optional[str]
    name: str
    description: str
    mac: Optional[str]
    model: str
    address: str
    is_online: bool
    last_online_at: Optional[str]
    last_offline_at: Optional[str]
    firmware_version: Optional[str]
    firmware_date: Optional[str]
    serial_number: Optional[str]
    is_battery_failure: bool
    is_power_failure: bool
    is_tampered: bool
    is_internal: bool
    controller_uuid: str
    is_details_verified: bool
    created_at: str
    updated_at: str
    vendor: str
    msp1_port: InterfacePanelMSP1Port
    controller: InterfacePanelController
    location_uuid: str
    customer_uuid: str

class InterfacePanelResponse(BaseModel):
    meta: InterfacePanelMeta
    data: InterfacePanelData


@app.get(
    "/api/v1/customers/{customer_id}/sequr/interfaces",
    name="get interface panels",
)
async def get_interface_panels(
    customer_id: int = Path(..., ge=1),
    customer_uuid: str = Query(..., min_length=1),
    controller_uuid: str = Query(..., min_length=1),
    order: str = Query("ASC"),
    order_by: str = Query("address"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=500),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    url = f"https://mercury-ac-api.sequr.io/v1/customer/{customer_uuid}/interface_panel"
    params = {
        "order": order,
        "order_by": order_by,
        "page": page,
        "page_size": page_size,
        "controller_uuid": controller_uuid,
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers, params=params)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )


class DoorCreateRequest(BaseModel):
    location_uuid: str
    name: str


@app.post(
    "/api/v1/customers/{customer_id}/sequr/createDoor",
    name="create door",
)
async def create_door(
    customer_id: int = Path(..., ge=1),
    customer_uuid: str = Query(..., min_length=1),
    payload: DoorCreateRequest = Body(...),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    url = f"https://mercury-ac-api.sequr.io/v1/customer/{customer_uuid}/door"

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.post(url, headers=headers, json=payload.dict())
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    # Forward upstream response (success or error) to the caller
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )


@app.get(
    "/api/v1/customers/{customer_id}/sequr/reader-port",
    name="get reader port",
)
async def get_reader_port(
    customer_id: int = Path(..., ge=1),
    customer_uuid: str = Query(..., min_length=1),
    controller_uuid: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    url = (
        f"https://mercury-ac-api.sequr.io/v1/customer/{customer_uuid}/reader_port"
        f"?controller_uuid={controller_uuid}"
    )

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    # Forward upstream response (success or error) to the caller
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )


@app.get(
    "/api/v1/customers/{customer_id}/sequr/output-point",
    name="output point",
)
async def get_output_point(
    customer_id: int = Path(..., ge=1),
    customer_uuid: str = Query(..., min_length=1),
    controller_uuid: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    url = (
        f"https://mercury-ac-api.sequr.io/v1/customer/{customer_uuid}/output_point"
        f"?controller_uuid={controller_uuid}"
    )

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )


@app.get(
    "/api/v1/customers/{customer_id}/sequr/input-point",
    name="input point",
)
async def get_input_point(
    customer_id: int = Path(..., ge=1),
    customer_uuid: str = Query(..., min_length=1),
    controller_uuid: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }

    url = (
        f"https://mercury-ac-api.sequr.io/v1/customer/{customer_uuid}/input_point"
        f"?controller_uuid={controller_uuid}"
    )

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.get(url, headers=headers)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )


class SaveDoorRequest(BaseModel):
    location_uuid: str
    controller_uuid: str
    reader_port_uuid: str
    door_strike_output_point_uuid: str | None = None
    door_position_input_point_uuid: str | None = None
    rex1_input_point_uuid: str | None = None
    rex2_input_point_uuid: str | None = None
    interface_panel_uuid: str
    reader_address: str | None = None
    osdp_secure: bool = False
    reader_port_baud_rate: int = 9600


@app.post(
    "/api/v1/customers/{customer_id}/sequr/save-door",
    name="save door hardware",
)
async def save_door(
    customer_id: int = Path(..., ge=1),
    door_uuid: str = Query(..., min_length=1),
    payload: SaveDoorRequest = Body(...),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    url = f"https://mercury-ac-api.sequr.io/v1/door/{door_uuid}/hardware"

    body = {
        "location_uuid": payload.location_uuid,
        "manufacturer": "MERCURY",
        "reader_model": "SIGNO_READER_20",
        "controller_uuid": payload.controller_uuid,
        "reader_access_type": "ACR_A_SINGLE",
        "reader_port_uuid": payload.reader_port_uuid,
        "reader_address": payload.reader_address,
        "door_strike_output_point_uuid": payload.door_strike_output_point_uuid,
        "door_position_input_point_uuid": payload.door_position_input_point_uuid,
        "rex1_input_point_uuid": payload.rex1_input_point_uuid,
        "rex2_input_point_uuid": payload.rex2_input_point_uuid,
        "osdp_secure": payload.osdp_secure,
        "interface_panel_uuid": payload.interface_panel_uuid,
        "reader_port_led_drive_mode": "OSDP",
        "reader_port_baud_rate": payload.reader_port_baud_rate,
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.put(url, headers=headers, json=body)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )

@app.post(
    "/api/v1/customers/{customer_id}/sequr/{controller_uuid}/interface-panel",
    response_model=InterfacePanelResponse,
    name="create interface panel"
)
async def create_interface_panel(
    customer_id: int = Path(..., ge=1),
    controller_uuid: str = Path(..., min_length=1),
    payload: InterfacePanelRequest = Body(...),
    db: Session = Depends(get_db),
):
    customer = crud.get_customer(db, customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    token = customer.secret_hash
    if not token:
        raise HTTPException(status_code=400, detail="No token available for this customer")

    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    url = f"https://mercury-ac-api.sequr.io/v1/controller/{controller_uuid}/interface_panel"

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            upstream = await client.post(url, headers=headers, json=payload.dict())
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {e}") from e
    # Forward upstream response (success or error) to the caller
    return Response(
        content=upstream.content,
        media_type=upstream.headers.get("content-type", "application/json"),
        status_code=upstream.status_code,
    )
