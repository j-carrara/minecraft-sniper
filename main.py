import sys
import os
from src.util import log
from src.sniper import name_wait

name_change = len(sys.argv) > 1 and '--name-change' in sys.argv[1:]

if not os.path.exists("tokens"):
    os.makedirs("tokens")
name = input("Input minecraft username to look for: ")
print("----------------------------------------------")
if name_change == True:
    log(f"Service started with --name-change, and can make name changes to your account automatically.", type="WARNING")

with open("users.txt", "r") as f:
    accounts = [line.strip() for line in f if line.strip()
                != "" and line.strip()[0] != "#"]

log(f"Found {len(accounts)} accounts in user file.")

try:
    name_wait(name, accounts, False)
except KeyboardInterrupt:
    log("Service stopped.")
