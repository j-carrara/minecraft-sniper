import sys
import os
from src.util import log
from src.sniper import name_wait

test = len(sys.argv) > 1 and '--no-change' in sys.argv[1:]

if not os.path.exists("tokens"):
    os.makedirs("tokens")
name = input("Input minecraft username to look for: ")
print("----------------------------------------------")
if test == True:
    log(f"Service started with --no-change, and will not make name changes automatically.", type="WARNING")

with open("users.txt", "r") as f:
    accounts = [line.strip() for line in f if line.strip()
                != "" and line.strip()[0] != "#"]

log(f"Found {len(accounts)} accounts in user file.")

try:
    name_wait(name, accounts, test)
except KeyboardInterrupt:
    log("Service stopped.")
