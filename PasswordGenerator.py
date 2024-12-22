import random
import string
import tkinter as tk
from tkinter import messagebox
from math import log2

def calculate_entropy(password):
    """
    Calculate the entropy of the given password.
    Entropy is measured in bits, higher entropy means stronger password.
    """
    # Create a set of all unique characters in the password
    unique_chars = set(password)
    # Determine the character pool size based on available characters
    pool_size = len(string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation)
    
    # Calculate the entropy using the formula: H = log2(pool_size^password_length)
    entropy = len(password) * log2(pool_size / len(unique_chars))
    return entropy

def password_strength_with_entropy(password):
    """
    Evaluates password strength based on entropy.
    """
    entropy = calculate_entropy(password)
    if entropy < 40:
        return "Weak: Password entropy is too low."
    elif entropy < 60:
        return "Medium: Password could be stronger."
    else:
        return "Strong: Password has high entropy!"

def generate_password(length=12, include_uppercase=True, include_numbers=True, include_symbols=True):
    """
    Generate a strong, random password based on user-defined criteria.
    """
    if length < 12:
        raise ValueError("Password length must be at least 12 characters.")
    if length > 100:
        raise ValueError("Password length cannot exceed 100 characters.")

    # Define character pools
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if include_uppercase else ''
    numbers = string.digits if include_numbers else ''
    symbols = string.punctuation if include_symbols else ''

    # Combine pools and ensure there's at least one character from each selected category
    all_characters = lowercase + uppercase + numbers + symbols
    if not all_characters:
        raise ValueError("At least one character type must be selected.")

    password = [
        random.choice(lowercase),
        random.choice(uppercase) if include_uppercase else '',
        random.choice(numbers) if include_numbers else '',
        random.choice(symbols) if include_symbols else ''
    ]

    # Fill the rest of the password length with random choices from all selected pools
    password += random.choices(all_characters, k=length - len(password))

    # Shuffle the password to ensure randomness
    random.shuffle(password)

    return ''.join(password)

def generate_password_ui():
    try:
        length = int(length_entry.get())
        if length > 100:
            messagebox.showwarning("Warning", "The maximum password length is 100.")
            return

        include_uppercase = uppercase_var.get()
        include_numbers = numbers_var.get()
        include_symbols = symbols_var.get()

        password = generate_password(
            length=length,
            include_uppercase=include_uppercase,
            include_numbers=include_numbers,
            include_symbols=include_symbols
        )

        # Limit display length to 50 characters
        display_password = password if len(password) <= 100 else password[:100] + "..."
        result_label.config(text=f"Generated Password: {display_password}")

        # Check password strength with entropy-based logic
        entropy_strength = password_strength_with_entropy(password)
        strength_label.config(text=entropy_strength)

        # Enable the copy button and store the full password for copying
        copy_button.config(state=tk.NORMAL)
        copy_button.password = password
    except ValueError as e:
        messagebox.showerror("Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", "An unexpected error occurred.")

def copy_to_clipboard():
    try:
        root.clipboard_clear()
        root.clipboard_append(copy_button.password)
        root.update()  # Update clipboard
        messagebox.showinfo("Success", "Password copied to clipboard!")
    except Exception as e:
        messagebox.showerror("Error", "Could not copy the password.")

def close_application():
    root.destroy()

# Create the GUI application
root = tk.Tk()
root.title("Password Generator with Entropy")
root.geometry("500x565")

# Title label
title_label = tk.Label(root, text="Password Generator with Entropy", font=("Arial", 18, "bold"))
title_label.pack(pady=20)

# Length label and entry
length_frame = tk.Frame(root)
length_frame.pack(pady=10)
length_label = tk.Label(length_frame, text="Password Length:")
length_label.pack(side="left", padx=5)
length_entry = tk.Entry(length_frame, width=10)
length_entry.pack(side="left", padx=5)
length_entry.insert(0, "12")

# Checkbuttons
options_frame = tk.Frame(root)
options_frame.pack(pady=10)
uppercase_var = tk.BooleanVar(value=True)
uppercase_check = tk.Checkbutton(options_frame, text="Include Uppercase Letters", variable=uppercase_var)
uppercase_check.pack(anchor="w", pady=2)
numbers_var = tk.BooleanVar(value=True)
numbers_check = tk.Checkbutton(options_frame, text="Include Numbers", variable=numbers_var)
numbers_check.pack(anchor="w", pady=2)
symbols_var = tk.BooleanVar(value=True)
symbols_check = tk.Checkbutton(options_frame, text="Include Symbols", variable=symbols_var)
symbols_check.pack(anchor="w", pady=2)

# Generate button
button_style = {"width": 20, "height": 2, "font": ("Arial", 12, "bold")}
generate_button = tk.Button(root, text="Generate Password", command=generate_password_ui, **button_style)
generate_button.pack(pady=15)

# Result label
result_label = tk.Label(root, text="", wraplength=400, justify="left")
result_label.pack(pady=10)

# Password strength label
strength_label = tk.Label(root, text="", wraplength=400, justify="left", font=("Arial", 10))
strength_label.pack(pady=10)

# Copy button
copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard, state=tk.DISABLED, **button_style)
copy_button.pack(pady=10)

# Exit button with red background and black text
close_button = tk.Button(root, text="Exit", command=close_application, bg="red", fg="black", **button_style)
close_button.pack(side="bottom", pady=10, fill="x")  # Use fill="x" to ensure it's always visible

# Run the application
root.mainloop()
