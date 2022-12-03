from datetime import datetime
from time import sleep

TIME_FORMAT = "%m-%d-%Y %H:%M:%S"
CLIENT_ID = "8259ec1b-539c-4ec9-b27b-c89f7c73bd31"
CLIENT_SECRET = ""
REDIRECT_URI = "http://localhost:8080/auth/callback"
SCOPES = "XboxLive.signin XboxLive.offline_access"


def log(message=None, type="INFO", end="\n"):
    if message == None:
        print(f"\r({datetime.now().strftime(TIME_FORMAT)})", end="")
    else:
        print(
            f"\r{datetime.now().strftime(('%m-%d-%Y %H:%M:%S'))}: {type}\t{message}", end=end)


def rate_limit(message):
    log(message+" (waiting 60s)")
    for _ in range(60):
        log()
        sleep(1)
    log("Coming back online.")
