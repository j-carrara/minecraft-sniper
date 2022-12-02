import os
import asyncio
import json
import requests
from time import sleep
from datetime import datetime, timedelta

from authentication import microsoft_auth, token_process
from util import log, rate_limit, TIME_FORMAT


def refresh_tokens(accounts):
    token_list = []
    tokens_pulled = 0
    timestamps = []

    log("Checking Microsoft token status.")
    microsoft_tokens = [asyncio.run(microsoft_auth(
        f".\\tokens", account)) for account in accounts]

    log("Retrieving tokens for Minecraft.")
    for i in range(2):
        for a, account in enumerate(accounts):
            if tokens_pulled > 0 and tokens_pulled % 3 == 0:
                rate_limit(
                    "Waiting before retrieving more tokens from server.")
            token, cached, timestamp = token_process(
                microsoft_tokens[a], account, i)
            timestamps.append(timestamp)
            token_list.append(token)
            if not cached:
                tokens_pulled = tokens_pulled + 1
                log(f'Token {i+1} for account "{account}" retrieved from server. ({len(token_list)-(i*5)}/{len(accounts)} accounts) ({i+1}/2 token sets)')
            else:
                log(f'Token {i+1} for account "{account}" retrieved from cache. ({len(token_list)-(i*5)}/{len(accounts)} accounts) ({i+1}/2 token sets)')

    return (token_list, min(timestamps))


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


if __name__ == "__main__":
    import sys

    test = len(sys.argv) > 1 and '--no-change' in sys.argv[1:]

    if not os.path.exists("tokens"):
        os.makedirs("tokens")
    name = input("Input minecraft username to look for: ")
    print("----------------------------------------------")
    if test == True:
        log(f"Service started in testing mode, and will not make name changes automatically.", type="DEBUG")

    with open("users.txt", "r") as f:
        accounts = [line.strip() for line in f if line.strip()
                    != "" and line.strip()[0] != "#"]

    log(f"Found {len(accounts)} accounts in user file.")

    try:
        name_wait(name, accounts, test)
    except KeyboardInterrupt:
        log("Service stopped.")
