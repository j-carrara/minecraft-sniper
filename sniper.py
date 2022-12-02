import os
import queue
from urllib.parse import parse_qs, urlparse
import webbrowser
import socket
import asyncio
from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.authentication.models import OAuth2TokenResponse
from xbox.webapi.common.signed_session import SignedSession
from xbox.webapi.scripts import CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
import json
import requests
from time import sleep
from datetime import datetime, timedelta
from yarl import URL
from typing import Optional

QUEUE = queue.Queue(1)
TIME_FORMAT = "%m-%d-%Y %H:%M:%S"

class AuthenticationManagerWithPrefill(AuthenticationManager):
    def generate_authorization_url(self, state: Optional[str] = None, account: str = None) -> str:
        """Generate Windows Live Authorization URL."""
        query_string = {
            "client_id": self._client_id,
            "response_type": "code",
            "approval_prompt": "auto",
            "scope": " ".join(self._scopes),
            "redirect_uri": self._redirect_uri,
            "login_hint": account
        }

        if state:
            query_string["state"] = state

        return str(
            URL("https://login.live.com/oauth20_authorize.srf").with_query(query_string)
        )

async def microsoft_auth(token_filepath: str, account: str):
    async with SignedSession() as session:
        auth_mgr = AuthenticationManagerWithPrefill(
            session, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
        )
        token_file = token_filepath + f"\\microsoft-token-{account}.json"

        # Refresh tokens if we have them
        if os.path.exists(token_file):
            with open(token_file) as f:
                tokens = f.read()
            auth_mgr.oauth = OAuth2TokenResponse.parse_raw(tokens)
            await auth_mgr.refresh_tokens()

        # Request new ones if they are not valid
        if not (auth_mgr.xsts_token and auth_mgr.xsts_token.is_valid()):
            
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("0.0.0.0", 8080))
            server_socket.listen(1)

            auth_url = auth_mgr.generate_authorization_url(account=account)
            webbrowser.open(auth_url)
            notification_text = f'Log in to "{account}".'
            log(notification_text, type="INPUT")


            client_connection, _ = server_socket.accept()
            request = client_connection.recv(8000).decode()
            response = 'HTTP/1.0 302 OK Found\nLocation: https://outlook.live.com/owa/logoff.owa'
            client_connection.sendall(response.encode())
            client_connection.close()
            server_socket.close()
            url_path = request.split(" ")[1]
            query_params = parse_qs(urlparse(url_path).query)
            auth_code = query_params.get("code")
            code = auth_code[0] if isinstance(auth_code, list) else auth_code
            # log(f'Log out of "{account}". Press [Enter] to continue after logging out.', type="INPUT", end="")
            # # sleep(1)
            # # webbrowser.open_new("https://live.com")
            # input()

            await auth_mgr.request_tokens(code)

        with open(token_file, mode="w") as f:
            f.write(auth_mgr.oauth.json())

        return auth_mgr.oauth.access_token

def get_xbl_token(microsoft_token):
    xbox = requests.post("https://user.auth.xboxlive.com/user/authenticate", headers={"Content-Type": "application/json", "Accept":"application/json" }, json= {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"d={microsoft_token}" 
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    })
    response = json.loads(xbox.content)
    return (response["Token"], response["DisplayClaims"]["xui"][0]["uhs"])

def get_xsts_token(xbl_token):
    xsts = requests.post("https://xsts.auth.xboxlive.com/xsts/authorize", headers={"Content-Type": "application/json", "Accept":"application/json" }, json= 
    {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [
                xbl_token
            ]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    })
    return json.loads(xsts.content)["Token"]

def get_minecraft_token(xsts_token, xbl_hash, account, sequence):
    try:
        with open(f".\\tokens\\minecraft-tokens.json", "r") as f: file_info = json.load(f)
    except:
        file_info = {}

    if account in file_info:
        if str(sequence) in file_info[account]:
            if datetime.now() - timedelta(hours=26) < datetime.strptime(file_info[account][str(sequence)]["timestamp"], TIME_FORMAT):
                return (file_info[account][str(sequence)]["token"], True, datetime.strptime(file_info[account][str(sequence)]["timestamp"], TIME_FORMAT))

    minecraft = requests.post("https://api.minecraftservices.com/authentication/login_with_xbox", headers={
        "Content-Type": "application/json",
        "user-agent": "Minecraft Development Personal Project",
        "Accept": "application/json"
    }, json=
    {
        "identityToken": f"XBL3.0 x={xbl_hash};{xsts_token}"
    })
    response = json.loads(minecraft.content)
    if "access_token" not in response:
        rate_limit("Token requests rate limited.")
        return get_minecraft_token(xsts_token, xbl_hash, account, sequence)
    token = f'Bearer {json.loads(minecraft.content)["access_token"]}'
    
    if account in file_info:
        file_info[account][str(sequence)] = {
            "timestamp": datetime.now().strftime(TIME_FORMAT),
            "token": token
        }
    else:
        file_info[account] = {
            str(sequence): {
                "timestamp": datetime.now().strftime(TIME_FORMAT),
                "token": token
            }
        }
    with open(f".\\tokens\\minecraft-tokens.json", "w") as f: json.dump(file_info, f)

    return (token, False, datetime.now())

def token_process(microsoft_token, account, sequence):
    xbl_token, xbl_hash = get_xbl_token(microsoft_token)
    xsts_token = get_xsts_token(xbl_token)
    return get_minecraft_token(xsts_token, xbl_hash, account, sequence)


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

def refresh_tokens(accounts):
    token_list = []
    tokens_pulled = 0
    timestamps = []
    
    log("Checking Microsoft token status.")
    microsoft_tokens = [asyncio.run(microsoft_auth(f".\\tokens", account)) for account in accounts]

    log("Retrieving tokens for Minecraft.")
    for i in range(2):
        for a, account in enumerate(accounts):
            if tokens_pulled > 0 and tokens_pulled % 3 == 0: 
                rate_limit("Waiting before retrieving more tokens from server.")
            token, cached, timestamp = token_process(microsoft_tokens[a], account, i)
            timestamps.append(timestamp)
            token_list.append(token)
            if not cached:
                tokens_pulled = tokens_pulled + 1
                log(f'Token {i+1} for account "{account}" retrieved from server. ({len(token_list)-(i*5)}/{len(accounts)} accounts) ({i+1}/2 token sets)')
            else:
                log(f'Token {i+1} for account "{account}" retrieved from cache. ({len(token_list)-(i*5)}/{len(accounts)} accounts) ({i+1}/2 token sets)')
    
    return (token_list, min(timestamps))

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
                    requests.put(f"https://api.minecraftservices.com/minecraft/profile/name/{name}", headers={"Authorization": tokens[0],})
                return True
            else:
                log()
        except Exception as e:   
            log(f"Error occured while checking availablity: {e}", type="ERROR")
        current_token = (current_token + 1) % len(tokens)
        sleep(10/len(tokens))

def log(message=None, type="INFO", end="\n"):
    if message == None:
        print(f"\r({datetime.now().strftime(TIME_FORMAT)})", end="")
    else:
        print(f"\r{datetime.now().strftime(('%m-%d-%Y %H:%M:%S'))}: {type}\t{message}", end=end)

def rate_limit(message):
    log(message+" (waiting 60s)")
    for _ in range(60):
        log()
        sleep(1)
    log("Coming back online.")


if __name__ == "__main__":
    import sys

    test = len(sys.argv) > 1 and '--no-change' in sys.argv[1:]
        
    if not os.path.exists("tokens"):
        os.makedirs("tokens")
    name = input("Input minecraft username to look for: ")
    print("----------------------------------------------")
    if test == True: log(f"Service started in testing mode, and will not make name changes automatically.", type="DEBUG")

    with open("users.txt", "r") as f:
        accounts = [line.strip() for line in f if line.strip() != "" and line.strip()[0] != "#"]

    log(f"Found {len(accounts)} accounts in user file.")

    try:
        name_wait(name, accounts, test)
    except KeyboardInterrupt:
        log("Service stopped.")