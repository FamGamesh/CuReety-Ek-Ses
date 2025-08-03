from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio
import json
import os
import uuid


from motor.motor_asyncio import AsyncIOMotorClient
import aiofiles
from io import BytesIO
import base64
import time
from collections import defaultdict
import websockets

import requests
import hashlib
import secrets

# Initialize FastAPI app
app = FastAPI(
    title="Personal Device Security API",
    description="Comprehensive API for personal device security and anti-theft protection",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "your-super-secret-jwt-key")

# Simple token storage (in production, use Redis or database)
active_tokens = {}

# MongoDB connection
MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017/security_app")
client = AsyncIOMotorClient(MONGO_URL)
db = client.security_app

# Collections
devices_collection = db.devices
users_collection = db.users
commands_collection = db.commands
logs_collection = db.logs
sessions_collection = db.sessions
locations_collection = db.locations
media_collection = db.media
files_collection = db.files
contacts_collection = db.contacts  
messages_collection = db.messages
calls_collection = db.calls
apps_collection = db.apps
notifications_collection = db.notifications

# WebSocket manager for real-time communication
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.device_connections: Dict[str, WebSocket] = {}
        
    async def connect(self, websocket: WebSocket, client_id: str, is_device: bool = False):
        await websocket.accept()
        if is_device:
            self.device_connections[client_id] = websocket
        else:
            self.active_connections[client_id] = websocket
            
    def disconnect(self, client_id: str, is_device: bool = False):
        if is_device:
            if client_id in self.device_connections:
                del self.device_connections[client_id]
        else:
            if client_id in self.active_connections:
                del self.active_connections[client_id]
                
    async def send_personal_message(self, message: str, client_id: str):
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_text(message)
            
    async def send_to_device(self, message: str, device_id: str):
        if device_id in self.device_connections:
            await self.device_connections[device_id].send_text(message)
            return True
        return False
        
    async def broadcast(self, message: str):
        for connection in self.active_connections.values():
            await connection.send_text(message)

manager = ConnectionManager()

# Authentication models
class PinAuth(BaseModel):
    pin: str
    device_id: Optional[str] = None

class ChangePin(BaseModel):
    new_pin: str

class EmergencyUnlock(BaseModel):
    device_id: str
    request_id: str

# Device models
class DeviceInfo(BaseModel):
    device_id: str
    device_name: str
    device_type: str
    os_version: str
    app_version: str
    last_seen: datetime
    status: str = "online"
    location: Optional[Dict] = None
    battery_level: Optional[int] = None
    storage_info: Optional[Dict] = None

class DeviceCommand(BaseModel):
    device_id: str
    command: str
    parameters: Optional[Dict] = {}
    priority: str = "normal"  # low, normal, high, emergency

class CommandResponse(BaseModel):
    command_id: str
    device_id: str
    status: str  # success, error, pending
    response_data: Optional[Dict] = {}
    timestamp: datetime
    error_message: Optional[str] = None

# Media models
class MediaFile(BaseModel):
    file_id: str
    device_id: str
    file_type: str  # photo, video, audio, document
    filename: str
    file_size: int
    created_date: datetime
    location: Optional[Dict] = None
    thumbnail: Optional[str] = None

# Location models
class LocationData(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    accuracy: float
    altitude: Optional[float] = None
    speed: Optional[float] = None
    bearing: Optional[float] = None
    timestamp: datetime
    location_method: str  # gps, network, passive

# Communication models
class CallLog(BaseModel):
    device_id: str
    call_type: str  # incoming, outgoing, missed
    phone_number: str
    contact_name: Optional[str] = None
    duration: int
    timestamp: datetime

class Message(BaseModel):
    device_id: str
    message_type: str  # sms, mms, whatsapp, etc.
    sender: str
    recipient: str
    content: str
    timestamp: datetime
    attachments: Optional[List[str]] = []

class Contact(BaseModel):
    device_id: str
    contact_id: str
    name: str
    phone_numbers: List[str]
    email_addresses: Optional[List[str]] = []
    photo: Optional[str] = None

# App models
class AppInfo(BaseModel):
    device_id: str
    package_name: str
    app_name: str
    version: str
    install_date: datetime
    permissions: List[str]
    usage_stats: Optional[Dict] = {}

# Notification models
class NotificationData(BaseModel):
    device_id: str
    app_package: str
    title: str
    content: str
    timestamp: datetime
    actions: Optional[List[str]] = []

# Security functions
def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode('utf-8')).hexdigest()

def verify_pin(pin: str, hashed: str) -> bool:
    return hashlib.sha256(pin.encode('utf-8')).hexdigest() == hashed

def create_jwt_token(data: dict) -> str:
    """Create a simple token without JWT library"""
    token = secrets.token_urlsafe(32)
    expire = datetime.utcnow() + timedelta(hours=24)
    active_tokens[token] = {
        **data,
        "exp": expire.timestamp()
    }
    return token

def verify_jwt_token(token: str) -> dict:
    """Verify token without JWT library"""
    if token not in active_tokens:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    token_data = active_tokens[token]
    if datetime.utcnow().timestamp() > token_data["exp"]:
        del active_tokens[token]
        raise HTTPException(status_code=401, detail="Token expired")
    
    return token_data

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return verify_jwt_token(credentials.credentials)

# Authentication endpoints
@app.post("/api/auth/pin")
async def authenticate_pin(pin_auth: PinAuth):
    """Authenticate with 6-digit PIN"""
    # Get user settings
    user = await users_collection.find_one({"user_id": "main_user"})
    if not user:
        # Create default user with PIN 123456
        default_pin = hash_pin("123456")
        user = {
            "user_id": "main_user",
            "pin_hash": default_pin,
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.utcnow()
        }
        await users_collection.insert_one(user)
    
    # Check if account is locked
    if user.get("locked_until") and datetime.utcnow() < user["locked_until"]:
        raise HTTPException(status_code=423, detail="Account locked. Try again later.")
    
    # Verify PIN
    if not verify_pin(pin_auth.pin, user["pin_hash"]):
        # Increment failed attempts
        failed_attempts = user.get("failed_attempts", 0) + 1
        update_data = {"failed_attempts": failed_attempts}
        
        if failed_attempts >= 10:
            # Lock account for 24 hours
            update_data["locked_until"] = datetime.utcnow() + timedelta(hours=24)
            
        await users_collection.update_one(
            {"user_id": "main_user"},
            {"$set": update_data}
        )
        
        raise HTTPException(status_code=401, detail=f"Invalid PIN. {10-failed_attempts} attempts remaining.")
    
    # Reset failed attempts on successful login
    await users_collection.update_one(
        {"user_id": "main_user"},
        {"$set": {"failed_attempts": 0, "locked_until": None}}
    )
    
    # Create JWT token
    token = create_jwt_token({"user_id": "main_user", "device_id": pin_auth.device_id})
    
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/auth/change-pin")
async def change_pin(pin_change: ChangePin, current_user: dict = Depends(get_current_user)):
    """Change PIN without requiring current PIN"""
    new_pin_hash = hash_pin(pin_change.new_pin)
    
    await users_collection.update_one(
        {"user_id": current_user["user_id"]},
        {"$set": {"pin_hash": new_pin_hash, "updated_at": datetime.utcnow()}}
    )
    
    return {"message": "PIN changed successfully"}

@app.post("/api/auth/emergency-unlock")
async def request_emergency_unlock(unlock_request: EmergencyUnlock, current_user: dict = Depends(get_current_user)):
    """Request emergency unlock approval from APK"""
    request_id = str(uuid.uuid4())
    
    # Send encrypted approval request to device
    command = {
        "command_id": request_id,
        "command": "emergency_unlock_request",
        "parameters": {
            "request_id": request_id,
            "frontend_user": current_user["user_id"]
        },
        "timestamp": datetime.utcnow()
    }
    
    # Store pending request
    await commands_collection.insert_one({
        **command,
        "device_id": unlock_request.device_id,
        "status": "pending"
    })
    
    # Send to device via WebSocket
    success = await manager.send_to_device(json.dumps(command), unlock_request.device_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Device not connected")
    
    return {"request_id": request_id, "message": "Emergency unlock request sent to device"}

# Device management endpoints
@app.post("/api/devices/register")
async def register_device(device_info: DeviceInfo):
    """Register a new device"""
    device_doc = device_info.dict()
    device_doc["registered_at"] = datetime.utcnow()
    device_doc["_id"] = device_info.device_id
    
    await devices_collection.replace_one(
        {"_id": device_info.device_id},
        device_doc,
        upsert=True
    )
    
    return {"message": "Device registered successfully"}

@app.get("/api/devices")
async def get_devices(current_user: dict = Depends(get_current_user)):
    """Get all registered devices"""
    devices = []
    async for device in devices_collection.find():
        devices.append(device)
    return devices

@app.get("/api/devices/{device_id}")
async def get_device_info(device_id: str, current_user: dict = Depends(get_current_user)):
    """Get specific device information"""
    device = await devices_collection.find_one({"_id": device_id})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@app.post("/api/devices/{device_id}/command")
async def send_device_command(device_id: str, command: DeviceCommand, current_user: dict = Depends(get_current_user)):
    """Send command to device"""
    command_id = str(uuid.uuid4())
    
    command_doc = {
        "command_id": command_id,
        "device_id": device_id,
        "command": command.command,
        "parameters": command.parameters,
        "priority": command.priority,
        "status": "pending",
        "sent_by": current_user["user_id"],
        "timestamp": datetime.utcnow()
    }
    
    await commands_collection.insert_one(command_doc)
    
    # Send to device via WebSocket
    success = await manager.send_to_device(json.dumps(command_doc), device_id)
    
    if not success:
        # Device offline, command will be queued
        await commands_collection.update_one(
            {"command_id": command_id},
            {"$set": {"status": "queued"}}
        )
    
    return {"command_id": command_id, "status": "sent" if success else "queued"}

# Core Security Features (1-10)
@app.post("/api/security/lock")
async def lock_device(device_id: str, current_user: dict = Depends(get_current_user)):
    """Remote device lock with custom PIN"""
    command = DeviceCommand(
        device_id=device_id,
        command="lock_device",
        priority="high"
    )
    return await send_device_command(device_id, command, current_user)

@app.post("/api/security/unlock")
async def unlock_device(device_id: str, current_user: dict = Depends(get_current_user)):
    """Remote device unlock"""
    command = DeviceCommand(
        device_id=device_id,
        command="unlock_device",
        priority="high"
    )
    return await send_device_command(device_id, command, current_user)

@app.post("/api/security/bypass-lock")
async def bypass_screen_lock(device_id: str, current_user: dict = Depends(get_current_user)):
    """Override existing screen locks"""
    command = DeviceCommand(
        device_id=device_id,
        command="bypass_screen_lock",
        priority="high"
    )
    return await send_device_command(device_id, command, current_user)

# Location & Tracking Features (11-20)
@app.get("/api/location/{device_id}")
async def get_device_location(device_id: str, current_user: dict = Depends(get_current_user)):
    """Get real-time device location"""
    command = DeviceCommand(
        device_id=device_id,
        command="get_location",
        priority="normal"
    )
    await send_device_command(device_id, command, current_user)
    
    # Return latest location from database
    location = await locations_collection.find_one(
        {"device_id": device_id},
        sort=[("timestamp", -1)]
    )
    return location

@app.get("/api/location/{device_id}/history")
async def get_location_history(device_id: str, hours: int = 24, current_user: dict = Depends(get_current_user)):
    """Get location history"""
    since = datetime.utcnow() - timedelta(hours=hours)
    locations = []
    
    async for location in locations_collection.find(
        {"device_id": device_id, "timestamp": {"$gte": since}},
        sort=[("timestamp", -1)]
    ):
        locations.append(location)
    
    return locations

@app.post("/api/location/{device_id}/geofence")
async def set_geofence(device_id: str, parameters: dict, current_user: dict = Depends(get_current_user)):
    """Set virtual boundaries with alerts"""
    command = DeviceCommand(
        device_id=device_id,
        command="set_geofence",
        parameters=parameters,
        priority="normal"
    )
    return await send_device_command(device_id, command, current_user)

# Communication Monitoring Features (21-38)
@app.get("/api/communication/calls/{device_id}")
async def get_call_logs(device_id: str, limit: int = 100, current_user: dict = Depends(get_current_user)):
    """Get call logs with filters"""
    calls = []
    async for call in calls_collection.find(
        {"device_id": device_id},
        sort=[("timestamp", -1)],
        limit=limit
    ):
        calls.append(call)
    return calls

@app.post("/api/communication/record-call")
async def start_call_recording(device_id: str, current_user: dict = Depends(get_current_user)):
    """Start live call recording"""
    command = DeviceCommand(
        device_id=device_id,
        command="start_call_recording",
        priority="high"
    )
    return await send_device_command(device_id, command, current_user)

@app.get("/api/communication/messages/{device_id}")
async def get_messages(device_id: str, app_type: str = "sms", limit: int = 100, current_user: dict = Depends(get_current_user)):
    """Get messages from various apps"""
    messages = []
    async for message in messages_collection.find(
        {"device_id": device_id, "message_type": app_type},
        sort=[("timestamp", -1)],
        limit=limit
    ):
        messages.append(message)
    return messages

@app.post("/api/communication/send-sms")
async def send_sms(device_id: str, recipient: str, content: str, current_user: dict = Depends(get_current_user)):
    """Send SMS remotely"""
    command = DeviceCommand(
        device_id=device_id,
        command="send_sms",
        parameters={"recipient": recipient, "content": content},
        priority="normal"
    )
    return await send_device_command(device_id, command, current_user)

@app.get("/api/communication/contacts/{device_id}")
async def get_contacts(device_id: str, current_user: dict = Depends(get_current_user)):
    """Get contact list"""
    contacts = []
    async for contact in contacts_collection.find({"device_id": device_id}):
        contacts.append(contact)
    return contacts

# App & System Control Features (39-50)
@app.get("/api/apps/{device_id}")
async def get_installed_apps(device_id: str, current_user: dict = Depends(get_current_user)):
    """Get list of installed apps"""
    command = DeviceCommand(
        device_id=device_id,
        command="get_installed_apps",
        priority="normal"
    )
    await send_device_command(device_id, command, current_user)
    
    # Return apps from database
    apps = []
    async for app in apps_collection.find({"device_id": device_id}):
        apps.append(app)
    return apps

@app.post("/api/apps/{device_id}/install")
async def install_app(device_id: str, package_name: str, apk_url: str, current_user: dict = Depends(get_current_user)):
    """Install app remotely"""
    command = DeviceCommand(
        device_id=device_id,
        command="install_app",
        parameters={"package_name": package_name, "apk_url": apk_url},
        priority="normal"
    )
    return await send_device_command(device_id, command, current_user)

@app.post("/api/apps/{device_id}/uninstall")
async def uninstall_app(device_id: str, package_name: str, current_user: dict = Depends(get_current_user)):
    """Uninstall app remotely"""
    command = DeviceCommand(
        device_id=device_id,
        command="uninstall_app",
        parameters={"package_name": package_name},
        priority="normal"
    )
    return await send_device_command(device_id, command, current_user)

@app.get("/api/system/notifications/{device_id}")
async def get_notifications(device_id: str, limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Get device notifications"""
    notifications = []
    async for notification in notifications_collection.find(
        {"device_id": device_id},
        sort=[("timestamp", -1)],
        limit=limit
    ):
        notifications.append(notification)
    return notifications

# Media & Surveillance Features (51-65)
@app.get("/api/media/screen/{device_id}/live")
async def get_live_screen(device_id: str, current_user: dict = Depends(get_current_user)):
    """Start live screen viewing"""
    command = DeviceCommand(
        device_id=device_id,
        command="start_screen_stream",
        priority="high"
    )
    return await send_device_command(device_id, command, current_user)

@app.post("/api/media/screen/{device_id}/record")
async def start_screen_recording(device_id: str, duration: int = 60, current_user: dict = Depends(get_current_user)):
    """Start screen recording"""
    command = DeviceCommand(
        device_id=device_id,
        command="start_screen_recording",
        parameters={"duration": duration},
        priority="high"
    )
    return await send_device_command(device_id, command, current_user)

@app.post("/api/media/camera/{device_id}/photo")
async def take_photo(device_id: str, camera: str = "back", current_user: dict = Depends(get_current_user)):
    """Take photo using device camera"""
    command = DeviceCommand(
        device_id=device_id,
        command="take_photo",
        parameters={"camera": camera},
        priority="normal"
    )
    return await send_device_command(device_id, command, current_user)

@app.post("/api/media/camera/{device_id}/video")
async def record_video(device_id: str, camera: str = "back", duration: int = 30, current_user: dict = Depends(get_current_user)):
    """Record video using device camera"""
    command = DeviceCommand(
        device_id=device_id,
        command="record_video",
        parameters={"camera": camera, "duration": duration},
        priority="normal"
    )
    return await send_device_command(device_id, command, current_user)

@app.post("/api/media/audio/{device_id}/record")
async def record_audio(device_id: str, duration: int = 60, current_user: dict = Depends(get_current_user)):
    """Record audio via microphone"""
    command = DeviceCommand(
        device_id=device_id,
        command="record_audio",
        parameters={"duration": duration},
        priority="normal"
    )
    return await send_device_command(device_id, command, current_user)

@app.get("/api/media/gallery/{device_id}")
async def get_gallery_files(device_id: str, file_type: str = "all", current_user: dict = Depends(get_current_user)):
    """Get gallery files"""
    query = {"device_id": device_id}
    if file_type != "all":
        query["file_type"] = file_type
        
    files = []
    async for file in media_collection.find(query, sort=[("created_date", -1)]):
        files.append(file)
    return files

# Continue with remaining endpoints... (This is getting quite long, so I'll continue in the next part)

# WebSocket endpoints for real-time communication
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle real-time messages
            await manager.send_personal_message(f"Echo: {data}", client_id)
    except WebSocketDisconnect:
        manager.disconnect(client_id)

@app.websocket("/ws/device/{device_id}")
async def device_websocket(websocket: WebSocket, device_id: str):
    await manager.connect(websocket, device_id, is_device=True)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle device responses
            response_data = json.loads(data)
            
            # Update device status
            await devices_collection.update_one(
                {"_id": device_id},
                {"$set": {"last_seen": datetime.utcnow(), "status": "online"}}
            )
            
            # Process response based on type
            if "command_id" in response_data:
                await commands_collection.update_one(
                    {"command_id": response_data["command_id"]},
                    {"$set": {
                        "status": response_data.get("status", "completed"),
                        "response_data": response_data.get("data", {}),
                        "completed_at": datetime.utcnow()
                    }}
                )
                
            # Broadcast to connected clients
            await manager.broadcast(data)
            
    except WebSocketDisconnect:
        manager.disconnect(device_id, is_device=True)
        await devices_collection.update_one(
            {"_id": device_id},
            {"$set": {"status": "offline", "last_seen": datetime.utcnow()}}
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
