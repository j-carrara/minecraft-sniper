import json
import requests
from time import sleep
from datetime import datetime, timedelta

from src.authentication import refresh_tokens
from src.util import log, rate_limit, TIME_FORMAT


def check_name(name, token):
    def request():
        req = requests.get(f"https://api.minecraftservices.com/minecraft/profile/name/{name}/available",
                           headers={
                               "authorization": token,
                           }
                           )
        return json.loads(req.content)
    content = request()

    while "status" not in content:
        if "error" in content:
            return False
        rate_limit("Availability check being rate limited.")
        content = request()
    return content["status"] == "AVAILABLE"


def name_wait(name, accounts, test=False):
    log(f"Retrieving tokens for all accounts.")
    tokens, token_time = refresh_tokens(accounts)
    log(f"Login tokens will expire on {token_time+timedelta(hours=24)}.")
    current_token = 0
    log(f'Name snipe service started for "{name}", will query every {10/len(tokens)}s for availability.')
    while True:
        if (datetime.now() - timedelta(hours=23)) > token_time:
            log(f"Tokens expiring soon, refreshing.")
            tokens, token_time = refresh_tokens(accounts)
            log(f"New login tokens will expire on {token_time}.")

        try:
            available = check_name(name, tokens[current_token])
            if available:
                log(f"{name} is now available: {datetime.now().strftime(TIME_FORMAT)}")
                if test == False:
                    requests.put(
                        f"https://api.minecraftservices.com/minecraft/profile/name/{name}", headers={"Authorization": tokens[0], })
                return True
            else:
                log()
        except Exception as e:
            log(f"Error occured while checking availablity: {e}", type="ERROR")
        current_token = (current_token + 1) % len(tokens)
        sleep(10/len(tokens))
