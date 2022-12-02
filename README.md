# Minecraft Sniper
Automatic Minecraft key authentication, name availability checking, and name claiming.

Every account doesn't need to own minecraft, but they must be set up with an Xbox profile.
More accounts means that the bot will probe for username availablity more often.

### Setup:

1. Ensure you have Python 3 installed.
2. Install the required modules from the requirements.txt:
```pip install -r requirements.txt```
3. Add your Microsoft accounts into the `users.txt`, one email per line.

**Adding the --name-change flag to your start command will turn on automatic name claiming.**

**Only the first account in users.txt will be used to claim a username.**

3. Run the program with:
```python main.py``` *or* ```python main.py --name-change```
4. The first time you run the program, your browser will prompt you to log into Microsoft for each account you listed.
5. ???
6. Profit.
