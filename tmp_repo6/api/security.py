from fastapi import APIRouter

router = APIRouter(
    prefix="/security",
    tags=["Security"]
)


@router.get("/")
def health():
    return {
        "message": "Security API Working"
    }