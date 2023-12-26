import bcrypt

# Set the original password
password = b"thisismypassword"

# Hash the password using bcrypt with a randomly generated salt
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

# Print the hashed password (this is what you would store in your database)
print("Hashed Password:", hashed)

# Prompt the user to enter a password for login
entered_password = input('Enter password to login: ')

# Convert the entered password to bytes using UTF-8 encoding
entered_password = bytes(entered_password, encoding='utf-8')

# Check if the entered password matches the stored hashed password
if bcrypt.checkpw(entered_password, hashed):
    print('Login Successful')
else:
    print('Invalid Password')
