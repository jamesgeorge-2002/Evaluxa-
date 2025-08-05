import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass
import sqlite3
import hashlib


class DatabaseManager:
    def __init__(self, db_name="evaluxa.db"):
        self.db_name = db_name
        # Initialize database connection
        self.conn = sqlite3.connect(self.db_name)
    
    def execute_query(self, query, params=()):
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

class AuthenticationManager:
    def __init__(self, db_manager):
        self.db = db_manager
    
    def login(self, username, password):
        # Simple login simulation
        if username == "admin" and password == "admin123":
            return True
        return False

class EvaluXaApp:
    def __init__(self, root):
        self.root = root
        self.db = DatabaseManager()
        self.auth = AuthenticationManager(self.db)
        self.setup_ui()
    
    def setup_ui(self):
        self.root.title("EvaluXa")
        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()
        
        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()
        
        tk.Button(self.root, text="Login", command=self.handle_login).pack()
    
    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if self.auth.login(username, password):
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Error", "Invalid credentials")

if __name__ == "__main__":
    root = tk.Tk()
    app = EvaluXaApp(root)
    root.mainloop()
# --- GUI Application ---
class EvaluXaApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EvaluXa - Exam Management System")
        self.root.geometry("800x600")
        
        self.db = DatabaseManager()
        self.auth = AuthenticationManager(self.db)
        
        self.show_login_screen()
    
    def show_login_screen(self):
        """Login Window"""
        self.clear_window()
        
        tk.Label(self.root, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=5)
        
        tk.Label(self.root, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)
        
        tk.Button(self.root, text="Login", command=self.login).pack(pady=20)
    
    def login(self):
        """Handle Login"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        user = self.auth.login(username, password)
        if user:
            self.show_dashboard(user.role)
        else:
            messagebox.showerror("Error", "Invalid credentials!")
    
    def show_dashboard(self, role):
        """Role-Based Dashboard"""
        self.clear_window()
        
        tk.Label(self.root, text=f"Welcome, {self.auth.current_user.full_name} ({role.title()})", 
                font=("Arial", 16)).pack(pady=20)
        
        # Teacher Dashboard
        if role == "teacher":
            tk.Button(self.root, text="Create Exam", command=self.show_create_exam).pack(pady=10)
            tk.Button(self.root, text="View Results", command=self.show_results).pack(pady=10)
        
        # Student Dashboard
        elif role == "student":
            tk.Button(self.root, text="Take Exam", command=self.show_available_exams).pack(pady=10)
            tk.Button(self.root, text="My Results", command=self.show_student_results).pack(pady=10)
        
        tk.Button(self.root, text="Logout", command=self.logout).pack(pady=20)
    
    def show_create_exam(self):
        """Exam Creation Form"""
        self.clear_window()
        
        tk.Label(self.root, text="Create New Exam", font=("Arial", 14)).pack(pady=10)
        
        # Form fields
        tk.Label(self.root, text="Title:").pack()
        title_entry = tk.Entry(self.root)
        title_entry.pack()
        
        tk.Label(self.root, text="Subject:").pack()
        subject_entry = tk.Entry(self.root)
        subject_entry.pack()
        
        tk.Button(self.root, text="Submit", 
                 command=lambda: self.save_exam(title_entry.get(), subject_entry.get())).pack(pady=20)
    
    def save_exam(self, title, subject):
        """Save exam to database (simplified example)"""
        if not title or not subject:
            messagebox.showerror("Error", "All fields are required!")
            return
        
        # Call your original ExamManager here
        messagebox.showinfo("Success", f"Exam '{title}' created!")
        self.show_dashboard("teacher")  # Return to dashboard
    
    def clear_window(self):
        """Remove all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def logout(self):
        self.auth.logout()
        self.show_login_screen()

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = EvaluXaApp(root)
    root.mainloop()