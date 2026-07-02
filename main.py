
from fastapi import FastAPI,HTTPException,status,Depends
from database import init_db,get_user,create_user
from models import UserRegister,Token,UserProfile
from auth import hash_password,verify_password,create_access_token, get_current_user
from fastapi.security import OAuth2PasswordRequestForm

app = FastAPI(title="OAuth2 Step-by-Step System")

#Ensure database tables exist on launch
@app.on_event("startup")
def on_startup():
  init_db()

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister):
    """Endpoint to register a fresh user with a hashed password."""
    existing_user = get_user(user_data.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # CRITICAL: Hash the plain password string before database insertion
    hashed = hash_password(user_data.password)
    success = create_user(user_data.username, hashed)
    
    if not success:
        raise HTTPException(status_code=500, detail="Database insertion error")
        
    return {"message": "User registered successfully"}




    
@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth2 compatible token login endpoint."""
    user = get_user(form_data.username)
    
    # 1. Validate user existence and pass the correct tuple index [1]
    if not user or not verify_password(form_data.password, user[1]):  # <-- Fixed here
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 2. Issue standard token payload using the username index [0]
    access_token = create_access_token(data={"sub": user[0]})         # <-- Fixed here
    return {"access_token": access_token, "token_type": "bearer"}

    


@app.get("/profile", response_model= UserProfile)
def get_profile(current_user: str = Depends(get_current_user)):
   """A fully protected route requiring valid Bearer Header tokens"""
   return {"username": current_user}