from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health_check():
    "Returns service liveness status."
    return {"status": "ok"}
