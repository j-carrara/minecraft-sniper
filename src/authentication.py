from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlparse
import webbrowser
import socket
import json
from datetime import datetime, timedelta

from src.util import log, rate_limit, TIME_FORMAT, CLIENT_ID, REDIRECT_URI, SCOPES


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
    query = {
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": authorization,
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
    }
    body = '&'.join([f"{field}={query[field]}" for field in query])
    content = urlopen(Request("https://login.live.com/oauth20_token.srf", headers={
                      "content-type": "application/x-www-form-urlencoded"}, data=body.encode("utf-8"), method="POST")).read()
    return (json.loads(content.decode("utf-8"))["access_token"], json.loads(content.decode("utf-8"))["refresh_token"])


def refresh_oauth_token(refresh):
    query = {
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "scope": SCOPES,
        "refresh_token": refresh,
    }
    body = '&'.join([f"{field}={query[field]}" for field in query])
    content = urlopen(Request("https://login.live.com/oauth20_token.srf", headers={
                      "content-type": "application/x-www-form-urlencoded"}, data=body.encode("utf-8"), method="POST")).read()
    return (json.loads(content.decode("utf-8"))["access_token"], json.loads(content.decode("utf-8"))["refresh_token"])


def get_xbl_token(microsoft_token):
    content = urlopen(Request(
        "https://user.auth.xboxlive.com/user/authenticate",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        data=json.dumps({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"d={microsoft_token}"
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        },
        ).encode("utf-8"), method="POST")).read()

    return (json.loads(content.decode("utf-8"))["Token"], json.loads(content.decode("utf-8"))["DisplayClaims"]["xui"][0]["uhs"])


def get_xsts_token(xbl_token):
    content = urlopen(Request(
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        data=json.dumps({
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [
                    xbl_token
                ]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }).encode("utf-8"), method="POST")).read()

    return json.loads(content.decode("utf-8"))["Token"]


def get_mc_token(xsts_token, xbl_hash):

    expiry = (datetime.now() + timedelta(seconds=86400)).strftime(TIME_FORMAT)
    content = urlopen(Request(
        "https://api.minecraftservices.com/authentication/login_with_xbox",
        headers={
            "Content-Type": "application/json",
            "user-agent": "Minecraft Development Personal Project",
            "Accept": "application/json"
        },
        data=json.dumps({
            "identityToken": f"XBL3.0 x={xbl_hash};{xsts_token}"
        }).encode("utf-8"),
        method="POST"
    )).read()

    response = json.loads(content.decode("utf-8"))
    if "access_token" not in response:
        rate_limit("Token requests rate limited.")
        return get_mc_token(xsts_token, xbl_hash)
    return (f'Bearer {response["access_token"]}', expiry)


def refresh_oauth(account):
    refresh_token = None

    try:
        with open("tokens.json", "r") as f:
            tokens = json.load(f)
            if account in tokens:
                refresh_token = tokens[account]["refresh_token"]
    except:
        tokens = {}

    if refresh_token == None:

        tokens[account] = {
            "0": {},
            "1": {}
        }

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", 8080))
        server_socket.listen(1)

        auth_url = generate_authorization_url(account=account)
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

        oauth_token, refresh_token = request_new_oauth_token(code)

    else:
        oauth_token, refresh_token = refresh_oauth_token(refresh_token)

    tokens[account]["oauth_token"] = oauth_token
    tokens[account]["refresh_token"] = refresh_token

    with open("tokens.json", "w") as f:
        json.dump(tokens, f)

    return oauth_token


def refresh_tokens(oauth_token, account, sequence):

    with open("tokens.json", "r") as f:
        tokens = json.load(f)
    if "expiry" in tokens[account][sequence]:
        if datetime.strptime(tokens[account][sequence]["expiry"], TIME_FORMAT) > datetime.now():
            return (tokens[account][sequence]["mc_token"], True, tokens[account][sequence]["expiry"])

    xbl_token, xbl_hash = get_xbl_token(oauth_token)
    xsts_token = get_xsts_token(xbl_token)
    mc_token, expiry_time = get_mc_token(xsts_token, xbl_hash)

    tokens[account][sequence]["mc_token"] = mc_token
    tokens[account][sequence]["expiry"] = expiry_time

    with open("tokens.json", "w") as f:
        json.dump(tokens, f)

    return (mc_token, False, tokens[account][sequence]["expiry"])


def refresh_all_tokens(accounts):
    token_list = []
    tokens_pulled = 0
    timestamps = []

    log("Checking Microsoft token status.")
    oauth_tokens = [refresh_oauth(account) for account in accounts]

    log("Retrieving tokens for Minecraft.")
    for i in range(2):
        for a, account in enumerate(accounts):
            if tokens_pulled > 0 and tokens_pulled % 3 == 0:
                rate_limit(
                    "Waiting before retrieving more tokens from server.")
            token, cached, timestamp = refresh_tokens(
                oauth_tokens[a], account, str(i))
            timestamps.append(datetime.strptime(timestamp, TIME_FORMAT))
            token_list.append(token)
            if not cached:
                tokens_pulled = tokens_pulled + 1
                log(f'Token {i+1} for account "{account}" retrieved from server. (Account: {len(token_list)-(i*len(accounts))}/{len(accounts)}) (Token: {i+1}/2)')
            else:
                log(f'Token {i+1} for account "{account}" retrieved from cache. (Account: {len(token_list)-(i*len(accounts))}/{len(accounts)}) (Token: {i+1}/2)')

    log(f"Login tokens will expire on {min(timestamps)}.")
    return (token_list, min(timestamps))
