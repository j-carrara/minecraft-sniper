import json
from time import sleep
from datetime import datetime, timedelta
from urllib.request import Request, urlopen

from src.authentication import refresh_all_tokens
from src.util import log, rate_limit, TIME_FORMAT


def check_name(name, token):
    def request():
        content = urlopen(Request(
            f"https://api.minecraftservices.com/minecraft/profile/name/{name}/available", 
            headers={"authorization": token}
        )).read()
        return json.loads(content.decode("utf-8"))
    content = request()

    while "status" not in content:
        if "error" in content:
            return False
        rate_limit("Availability check being rate limited.")
        content = request()
    return content["status"] == "AVAILABLE"


def name_wait(name, accounts, name_change=False):
    log(f"Retrieving tokens for all accounts.")
    tokens, token_time = refresh_all_tokens(accounts)
    current_token = 0
    log(f'Name snipe service started for "{name}", will query every {10/len(tokens)}s for availability.')
    while True:
        if (datetime.now() + timedelta(hours=1)) > token_time:
            log(f"Tokens expiring soon, refreshing.")
            tokens, token_time = refresh_all_tokens(accounts)

        try:
            available = check_name(name, tokens[current_token])
            if available:
                log(f"{name} is now available: {datetime.now().strftime(TIME_FORMAT)}")
                if name_change == True:
                    urlopen(Request(
                        f"https://api.minecraftservices.com/minecraft/profile/name/{name}", 
                        headers={"Authorization": tokens[0]},
                        method='PUT'
                    ))
                return True
            else:
                log()
        except Exception as e:
            log(f"Error occured while checking availablity: {e}", type="ERROR")
        current_token = (current_token + 1) % len(tokens)
        sleep(10/len(tokens))
