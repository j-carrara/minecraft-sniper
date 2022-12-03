
from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.authentication.models import OAuth2TokenResponse
from xbox.webapi.common.signed_session import SignedSession
from xbox.webapi.scripts import CLIENT_ID, CLIENT_SECRET, REDIRECT_URI

import requests
from urllib.parse import parse_qs, urlparse
from yarl import URL

import webbrowser
import os
import socket
import json
import queue
from datetime import datetime, timedelta
from typing import Optional
import asyncio

from src.util import log, rate_limit, TIME_FORMAT

QUEUE = queue.Queue(1)


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


async def get_xsts_token(account: str):
    async with SignedSession() as session:
        auth_mgr = AuthenticationManagerWithPrefill(
            session, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
        )
        token_file = f".\\tokens\\microsoft-token-{account}.json"

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

            await auth_mgr.request_tokens(code)

        with open(token_file, mode="w") as f:
            f.write(auth_mgr.oauth.json())
        print(auth_mgr.xsts_token.json())
        xsts_token = json.loads(auth_mgr.xsts_token.json())
        return (xsts_token["token"], xsts_token["display_claims"]["xui"][0]["uhs"])



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
    xsts_tokens = [asyncio.run(get_xsts_token(account)) for account in accounts]

    log("Retrieving tokens for Minecraft.")
    for i in range(2):
        for a, account in enumerate(accounts):
            if tokens_pulled > 0 and tokens_pulled % 3 == 0:
                rate_limit(
                    "Waiting before retrieving more tokens from server.")
            token, cached, timestamp = get_minecraft_token(xsts_tokens[a][0], xsts_tokens[a][1], account, i)
            timestamps.append(timestamp)
            token_list.append(token)
            if not cached:
                tokens_pulled = tokens_pulled + 1
                log(f'Token {i+1} for account "{account}" retrieved from server. ({len(token_list)-(i*5)}/{len(accounts)} accounts) ({i+1}/2 token sets)')
            else:
                log(f'Token {i+1} for account "{account}" retrieved from cache. ({len(token_list)-(i*5)}/{len(accounts)} accounts) ({i+1}/2 token sets)')

    log(f"Login tokens will expire on {min(timestamps)+timedelta(hours=24)}.")
    return (token_list, min(timestamps))
