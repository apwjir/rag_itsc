from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware 
from contextlib import asynccontextmanager
import qdrant_client

from app.services.ai_engine import ai_engine_instance
from app.services.auto_worker import run_auto_worker
from threading import Thread, Event

from app.api.auth import router as auth_router 
from app.api.auto_analyze import router as auto_analyze_router
from app.api.soc_action import router as soc_action_router
from app.api.dashboard import router as dashboard_router
from app.api.users import router as users_router
from app.api.summary import router as summary_router
from app.api.logs import router as logs_router
from app.api.ai import router as ai_router
from app.api.health import router as health_router

stop_event = Event()
worker_thread: Thread | None = None

# --- Lifespan Manager ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker_thread
    print("🚀 Server Starting... Initializing AI Engine...")
    
    # --- 🔍 แก้เป็นบรรทัดนี้ครับ ---
    print(f"🔎 DEBUG: Module Path = {qdrant_client}") 
    # (ถ้ามันโหลดถูกที่ ต้องมีคำว่า 'site-packages' ใน Path ที่แสดงออกมา)
    
    # --- ส่วนเช็ค search method เก็บไว้เหมือนเดิม ---
    try:
        ai_engine_instance.init_models()

        stop_event.clear()

        if not worker_thread or not worker_thread.is_alive():
            worker_thread = Thread(
                target=run_auto_worker,
                args=(stop_event,),
                daemon=True,
            )
            worker_thread.start()
            print("Auto worker thread started")
        else:
            print("ℹ️ Auto worker thread already running")

        if ai_engine_instance.client is None:
            print("Qdrant not connected")
        else:
            print("Qdrant client OK")

    except Exception as e:
        print(f"💥 Error during init: {e}")
    yield

    stop_event.set()
    if worker_thread and worker_thread.is_alive():
        worker_thread.join(timeout=5)
    print("🛑 Server Stopping...")
    
app = FastAPI(lifespan=lifespan)

#--- CORS Middleware ---
origins = [
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Include Routers ---
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(auto_analyze_router, tags=["Auto Analysis"])
app.include_router(soc_action_router)
app.include_router(dashboard_router)
app.include_router(users_router)
app.include_router(summary_router)
app.include_router(logs_router, tags=["Logs"])
app.include_router(ai_router, tags=["AI"])
app.include_router(health_router)
