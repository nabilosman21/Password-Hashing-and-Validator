from tkinter import *
import bcrypt

def validate(password):
    # The hashed password (use your actual hashed password)
    hashed_password = b'$2b$12$6u/TDoyulkFEVtJZ7atMheDHsisgvn3Bf39YITN1JMqKfa6.LV4tu'

    # Convert the entered password to bytes
    entered_password = bytes(password, encoding='utf-8')

    # Check if the entered password matches the hashed password
    if bcrypt.checkpw(entered_password, hashed_password):
        print('Login Successful')
    else:
        print('Invalid Password')

root = Tk()
root.geometry("300x300")
root.title("Password Validation")

password_label = Label(root, text="Enter Password:")
password_label.pack()

password_entry = Entry(root, show="*")  # Use show="*" to hide entered characters
password_entry.pack()

button = Button(root, text="Validate", command=lambda: validate(password_entry.get()))
button.pack()

root.mainloop()
