# Minecraft Sniper
Automatic Minecraft key authentication, name availabilty checking, and name claiming.

Add your Microsoft accounts into the `users.txt`, one email per line.
Every account doesn't need to own minecraft, but they must be set up with an Xbox profile.
More accounts means that the bot will probe for username availablity more often.

**The first account in the users.txt needs to own Minecraft, and will automatically be used to claim the name if it becomes available.**

**Adding a --no-change flag to your start command will turn off automatic name changing, and will instead notify you if the name becomes available. (see step 5 of setup)**

### Setup:

1. Ensure you have Python 3 installed.
2. Install the required modules from the requirements.txt:
```pip install -r requirements.txt```
3. Run the program with:
```python sniper.py``` *or* ```python sniper.py --no-change```
4. The first time you run the program, your browser will prompt you to log into Microsoft for each account you listed.
5. ???
6. Profit.