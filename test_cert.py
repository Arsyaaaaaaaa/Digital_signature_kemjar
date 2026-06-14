import sys
import traceback

try:
    from crypto_utils import generate_user_certificate
    generate_user_certificate(1, "Test User", "test@user.com")
    print("Success")
except Exception as e:
    traceback.print_exc()
