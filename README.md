# Minecraft Username Sniper
Automatic Minecraft key authentication, name availability checking, and name claiming.

### Setup:

1. Ensure you have Python 3 installed. No libraries are required for this module.
2. Add your Microsoft accounts into the `users.txt`, one email per line.

Every account doesn't need to own minecraft, but they must be set up with an Xbox profile.
More accounts means that the bot will probe for username availablity more often,
but it seems that **more than 5 accounts runs into issues with rate limiting.**

3. Run the program with:
```python main.py``` *or* ```python main.py --name-change```

**Adding the --name-change flag to your start command will turn on automatic name claiming.**

**Only the first account in users.txt will be used to claim a username.**

4. The first time you run the program, your browser will prompt you to log into Microsoft for each account you listed.
5. ???
6. Profit.
