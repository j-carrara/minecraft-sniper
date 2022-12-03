
from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.authentication.models import OAuth2TokenResponse
from xbox.webapi.common.signed_session import SignedSession

import requests
from urllib.parse import parse_qs, urlparse

import webbrowser
import os
import socket
import json
from datetime import datetime, timedelta
import asyncio

from src.util import log, rate_limit, TIME_FORMAT, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SCOPES


def build_url(url, query_fields):
    return url+"?"+'&'.join([f"{field}={query_fields[field]}" for field in query_fields if query_fields[field] != ""])


def generate_authorization_url(account=None) -> str:
    query_fields = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "approval_prompt": "auto",
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "login_hint": account
    }

    return build_url("https://login.live.com/oauth20_authorize.srf", query_fields)


def request_new_oauth_token(authorization):
    response = requests.post("https://login.live.com/oauth20_token.srf", headers={"content-type": "application/x-www-form-urlencoded"}, data={
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": authorization,
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
    })
    return (json.loads(response.content)["access_token"], json.loads(response.content)["refresh_token"])


def refresh_oauth_token(refresh):
    response = requests.post("https://login.live.com/oauth20_token.srf", headers={"content-type": "application/x-www-form-urlencoded"}, data={
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "scope": SCOPES,
        "refresh_token": refresh,
        }
    )
    print(response.content)
    return (json.loads(response.content)["access_token"], json.loads(response.content)["refresh_token"])


def get_xbl_token(microsoft_token):
    xbox = requests.post("https://user.auth.xboxlive.com/user/authenticate",
                         headers={
                             "Content-Type": "application/json",
                             "Accept": "application/json"},
                         json={
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
    xsts = requests.post("https://xsts.auth.xboxlive.com/xsts/authorize",
                         headers={
                             "Content-Type": "application/json",
                             "Accept": "application/json"
                         },
                         json={
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

class AuthenticationManagerWithPrefill(AuthenticationManager):

    async def request_tokens(self, authorization_code: str) -> None:
        self.oauth = await self.request_oauth_token(authorization_code)
        self.user_token = await self.request_user_token()
        self.xsts_token = await self.request_xsts_token(relying_party="rp://api.minecraftservices.com/")

    async def refresh_tokens(self) -> None:
        if not (self.oauth and self.oauth.is_valid()):
            self.oauth = await self.refresh_oauth_token()
        if not (self.user_token and self.user_token.is_valid()):
            self.user_token = await self.request_user_token()
        if not (self.xsts_token and self.xsts_token.is_valid()):
            self.xsts_token = await self.request_xsts_token(relying_party="rp://api.minecraftservices.com/")


# async def get_xsts_token(account: str):
#     async with SignedSession() as session:
#         auth_mgr = AuthenticationManagerWithPrefill(
#             session, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
#         )
#         token_file = f".\\tokens\\microsoft-token-{account}.json"

#         # Refresh tokens if we have them
#         if os.path.exists(token_file):
#             with open(token_file) as f:
#                 tokens = f.read()
#             auth_mgr.oauth = OAuth2TokenResponse.parse_raw(tokens)
#             await auth_mgr.refresh_tokens()

#         # Request new ones if they are not valid
#         if not (auth_mgr.xsts_token and auth_mgr.xsts_token.is_valid()):

#             server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#             server_socket.bind(("0.0.0.0", 8080))
#             server_socket.listen(1)

#             auth_url = generate_authorization_url(account=account)
#             webbrowser.open(auth_url)
#             notification_text = f'Log in to "{account}".'
#             log(notification_text, type="INPUT")

#             client_connection, _ = server_socket.accept()
#             request = client_connection.recv(8000).decode()
#             response = 'HTTP/1.0 302 OK Found\nLocation: https://outlook.live.com/owa/logoff.owa'
#             client_connection.sendall(response.encode())
#             client_connection.close()
#             server_socket.close()
#             url_path = request.split(" ")[1]
#             query_params = parse_qs(urlparse(url_path).query)
#             auth_code = query_params.get("code")
#             code = auth_code[0] if isinstance(auth_code, list) else auth_code

#             await auth_mgr.request_tokens(code)

#         with open(token_file, mode="w") as f:
#             f.write(auth_mgr.oauth.json())
#         xsts_token = json.loads(auth_mgr.xsts_token.json())
#         return (xsts_token["token"], xsts_token["display_claims"]["xui"][0]["uhs"])


def get_minecraft_token(xsts_token, xbl_hash, account, sequence):
    try:
        with open(f".\\tokens\\minecraft-tokens.json", "r") as f:
            file_info = json.load(f)
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
    }, json={
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
    with open(f".\\tokens\\minecraft-tokens.json", "w") as f:
        json.dump(file_info, f)

    return (token, False, datetime.now())


def refresh_tokens(accounts):
    token_list = []
    tokens_pulled = 0
    timestamps = []

    log("Checking Microsoft token status.")
    xsts_tokens = [asyncio.run(get_xsts_token(account))
                   for account in accounts]

    log("Retrieving tokens for Minecraft.")
    for i in range(2):
        for a, account in enumerate(accounts):
            if tokens_pulled > 0 and tokens_pulled % 3 == 0:
                rate_limit(
                    "Waiting before retrieving more tokens from server.")
            token, cached, timestamp = get_minecraft_token(
                xsts_tokens[a][0], xsts_tokens[a][1], account, i)
            timestamps.append(timestamp)
            token_list.append(token)
            if not cached:
                tokens_pulled = tokens_pulled + 1
                log(f'Token {i+1} for account "{account}" retrieved from server. ({len(token_list)-(i*len(accounts))}/{len(accounts)} accounts) ({i+1}/2 token sets)')
            else:
                log(f'Token {i+1} for account "{account}" retrieved from cache. ({len(token_list)-(i*len(accounts))}/{len(accounts)} accounts) ({i+1}/2 token sets)')

    log(f"Login tokens will expire on {min(timestamps)+timedelta(hours=24)}.")
    return (token_list, min(timestamps))
