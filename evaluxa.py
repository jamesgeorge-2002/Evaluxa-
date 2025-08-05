"""
EvaluXa - Comprehensive Exam Management System
A complete solution for teachers, students, and parents
"""

import sqlite3
import hashlib
import datetime
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns # For better visualization
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
import time

# Data Classes
@dataclass
class User:
    user_id: int
    username: str
    email: str
    role: str  # 'teacher', 'student', 'parent'
    full_name: str
    created_at: str

@dataclass
class Question:
    question_id: int
    exam_id: int
    question_text: str
    options: List[str]
    correct_answer: int
    points: int
    difficulty: str

@dataclass
class Exam:
    exam_id: int
    title: str
    description: str
    teacher_id: int
    subject: str
    duration_minutes: int
    total_points: int
    start_time: str
    end_time: str
    is_active: bool

@dataclass
class ExamResult:
    result_id: int
    exam_id: int
    student_id: int
    score: float
    total_points: int
    percentage: float
    time_taken: int
    submitted_at: str
    answers: Dict

class DatabaseManager:
    def __init__(self, db_name="evaluxa.db"):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        """Initialize database with all required tables"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT NOT NULL,
                phone TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Student-Parent relationship
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS student_parent (
                student_id INTEGER,
                parent_id INTEGER,
                relationship TEXT DEFAULT 'parent',
                FOREIGN KEY (student_id) REFERENCES users (user_id),
                FOREIGN KEY (parent_id) REFERENCES users (user_id),
                PRIMARY KEY (student_id, parent_id)
            )
        ''')
        
        # Classes/Groups
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS classes (
                class_id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_name TEXT NOT NULL,
                teacher_id INTEGER,
                subject TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (teacher_id) REFERENCES users (user_id)
            )
        ''')
        
        # Student enrollment in classes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS class_enrollment (
                class_id INTEGER,
                student_id INTEGER,
                enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (class_id) REFERENCES classes (class_id),
                FOREIGN KEY (student_id) REFERENCES users (user_id),
                PRIMARY KEY (class_id, student_id)
            )
        ''')
        
        # Exams table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exams (
                exam_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                teacher_id INTEGER,
                class_id INTEGER,
                subject TEXT,
                duration_minutes INTEGER DEFAULT 60,
                total_points INTEGER DEFAULT 0,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                allow_retake BOOLEAN DEFAULT 0,
                show_results BOOLEAN DEFAULT 1,
                randomize_questions BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (teacher_id) REFERENCES users (user_id),
                FOREIGN KEY (class_id) REFERENCES classes (class_id)
            )
        ''')
        
        # Questions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS questions (
                question_id INTEGER PRIMARY KEY AUTOINCREMENT,
                exam_id INTEGER,
                question_text TEXT NOT NULL,
                question_type TEXT DEFAULT 'multiple_choice',
                options TEXT, -- JSON string for options
                correct_answer TEXT,
                points INTEGER DEFAULT 1,
                difficulty TEXT DEFAULT 'medium',
                explanation TEXT,
                FOREIGN KEY (exam_id) REFERENCES exams (exam_id)
            )
        ''')
        
        # Exam attempts/results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exam_results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                exam_id INTEGER,
                student_id INTEGER,
                attempt_number INTEGER DEFAULT 1,
                score REAL,
                total_points INTEGER,
                percentage REAL,
                time_taken INTEGER, -- in seconds
                answers TEXT, -- JSON string
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_completed BOOLEAN DEFAULT 1,
                FOREIGN KEY (exam_id) REFERENCES exams (exam_id),
                FOREIGN KEY (student_id) REFERENCES users (user_id)
            )
        ''')
        
        # Re-exam requests
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reexam_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                exam_id INTEGER,
                student_id INTEGER,
                reason TEXT,
                status TEXT DEFAULT 'pending', -- pending, approved, rejected
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                reviewed_by INTEGER,
                teacher_comments TEXT,
                FOREIGN KEY (exam_id) REFERENCES exams (exam_id),
                FOREIGN KEY (student_id) REFERENCES users (user_id),
                FOREIGN KEY (reviewed_by) REFERENCES users (user_id)
            )
        ''')
        
        # Notifications
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                message TEXT,
                type TEXT DEFAULT 'info',
                is_read BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # System logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Create default admin user if not exists
        self.create_default_admin()
    
    def create_default_admin(self):
        """Create default admin user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if cursor.fetchone()[0] == 0:
            admin_password = self.hash_password("admin123")
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role, full_name)
                VALUES (?, ?, ?, ?, ?)
            ''', ("admin", admin_password, "admin@evaluxa.com", "admin", "System Administrator"))
            conn.commit()
        
        conn.close()
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def execute_query(self, query: str, params: tuple = ()) -> List:
        """Execute a query and return results"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        return results
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute an update/insert query and return affected rows"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(query, params)
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        return affected_rows

class AuthenticationManager:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.current_user = None
        self.session_token = None
    
    def register_user(self, username: str, password: str, email: str, role: str, full_name: str, phone: str = "") -> bool:
        """Register a new user"""
        try:
            password_hash = self.db.hash_password(password)
            query = '''
                INSERT INTO users (username, password_hash, email, role, full_name, phone)
                VALUES (?, ?, ?, ?, ?, ?)
            '''
            self.db.execute_update(query, (username, password_hash, email, role, full_name, phone))
            return True
        except sqlite3.IntegrityError:
            return False
    
    def login(self, username: str, password: str) -> Optional[User]:
        """Authenticate user login"""
        password_hash = self.db.hash_password(password)
        query = '''
            SELECT user_id, username, email, role, full_name, created_at
            FROM users 
            WHERE username = ? AND password_hash = ? AND is_active = 1
        '''
        result = self.db.execute_query(query, (username, password_hash))
        
        if result:
            user_data = result[0]
            self.current_user = User(
                user_id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                role=user_data[3],
                full_name=user_data[4],
                created_at=user_data[5]
            )
            self.session_token = str(uuid.uuid4())
            self.log_action("login", f"User {username} logged in successfully")
            return self.current_user
        return None
    
    def logout(self):
        """Logout current user"""
        if self.current_user:
            self.log_action("logout", f"User {self.current_user.username} logged out")
        self.current_user = None
        self.session_token = None
    
    def log_action(self, action: str, details: str):
        """Log user actions"""
        if self.current_user:
            query = '''
                INSERT INTO system_logs (user_id, action, details)
                VALUES (?, ?, ?)
            '''
            self.db.execute_update(query, (self.current_user.user_id, action, details))

class ExamManager:
    def __init__(self, db_manager: DatabaseManager, auth_manager: AuthenticationManager):
        self.db = db_manager
        self.auth = auth_manager
    
    def create_exam(self, title: str, description: str, class_id: int, subject: str, 
                   duration_minutes: int, start_time: str, end_time: str) -> int:
        """Create a new exam"""
        if self.auth.current_user.role != 'teacher':
            raise PermissionError("Only teachers can create exams")
        
        query = '''
            INSERT INTO exams (title, description, teacher_id, class_id, subject, 
                             duration_minutes, start_time, end_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        cursor.execute(query, (title, description, self.auth.current_user.user_id, 
                              class_id, subject, duration_minutes, start_time, end_time))
        exam_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        self.auth.log_action("create_exam", f"Created exam: {title}")
        return exam_id
    
    def add_question(self, exam_id: int, question_text: str, options: List[str], 
                    correct_answer: str, points: int = 1, difficulty: str = "medium",
                    explanation: str = "") -> int:
        """Add a question to an exam"""
        if self.auth.current_user.role != 'teacher':
            raise PermissionError("Only teachers can add questions")
        
        options_json = json.dumps(options)
        query = '''
            INSERT INTO questions (exam_id, question_text, options, correct_answer, 
                                 points, difficulty, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        cursor.execute(query, (exam_id, question_text, options_json, correct_answer, 
                              points, difficulty, explanation))
        question_id = cursor.lastrowid
        
        # Update total points for the exam
        cursor.execute("UPDATE exams SET total_points = total_points + ? WHERE exam_id = ?", 
                      (points, exam_id))
        
        conn.commit()
        conn.close()
        
        return question_id
    
    def get_exam_questions(self, exam_id: int) -> List[Dict]:
        """Get all questions for an exam"""
        query = '''
            SELECT question_id, question_text, options, correct_answer, points, difficulty, explanation
            FROM questions WHERE exam_id = ?
        '''
        results = self.db.execute_query(query, (exam_id,))
        
        questions = []
        for row in results:
            questions.append({
                'question_id': row[0],
                'question_text': row[1],
                'options': json.loads(row[2]),
                'correct_answer': row[3],
                'points': row[4],
                'difficulty': row[5],
                'explanation': row[6]
            })
        
        return questions
    
    def submit_exam(self, exam_id: int, answers: Dict) -> int:
        """Submit exam answers and calculate score"""
        if self.auth.current_user.role != 'student':
            raise PermissionError("Only students can submit exams")
        
        questions = self.get_exam_questions(exam_id)
        score = 0
        total_points = 0
        
        for question in questions:
            total_points += question['points']
            student_answer = answers.get(str(question['question_id']), "")
            if student_answer == question['correct_answer']:
                score += question['points']
        
        percentage = (score / total_points * 100) if total_points > 0 else 0
        
        # Check attempt number
        attempt_query = '''
            SELECT COUNT(*) FROM exam_results 
            WHERE exam_id = ? AND student_id = ?
        '''
        attempt_count = self.db.execute_query(attempt_query, (exam_id, self.auth.current_user.user_id))[0][0]
        
        query = '''
            INSERT INTO exam_results (exam_id, student_id, attempt_number, score, 
                                    total_points, percentage, answers)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        cursor.execute(query, (exam_id, self.auth.current_user.user_id, attempt_count + 1,
                              score, total_points, percentage, json.dumps(answers)))
        result_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        self.auth.log_action("submit_exam", f"Submitted exam {exam_id} with score {score}/{total_points}")
        return result_id
    
    def get_student_exams(self, student_id: int = None) -> List[Dict]:
        """Get available exams for a student"""
        if student_id is None:
            student_id = self.auth.current_user.user_id
        
        query = '''
            SELECT e.exam_id, e.title, e.description, e.subject, e.duration_minutes,
                   e.start_time, e.end_time, e.total_points, u.full_name as teacher_name,
                   c.class_name
            FROM exams e
            JOIN users u ON e.teacher_id = u.user_id
            JOIN classes c ON e.class_id = c.class_id
            JOIN class_enrollment ce ON c.class_id = ce.class_id
            WHERE ce.student_id = ? AND e.is_active = 1
            ORDER BY e.start_time DESC
        '''
        results = self.db.execute_query(query, (student_id,))
        
        exams = []
        for row in results:
            exams.append({
                'exam_id': row[0],
                'title': row[1],
                'description': row[2],
                'subject': row[3],
                'duration_minutes': row[4],
                'start_time': row[5],
                'end_time': row[6],
                'total_points': row[7],
                'teacher_name': row[8],
                'class_name': row[9]
            })
        
        return exams

class ReportManager:
    def __init__(self, db_manager: DatabaseManager, auth_manager: AuthenticationManager):
        self.db = db_manager
        self.auth = auth_manager
    
    def generate_student_report(self, student_id: int, exam_id: int = None) -> Dict:
        """Generate comprehensive student report"""
        if exam_id:
            # Single exam report
            query = '''
                SELECT er.score, er.total_points, er.percentage, er.time_taken,
                       er.submitted_at, e.title, e.subject, er.attempt_number
                FROM exam_results er
                JOIN exams e ON er.exam_id = e.exam_id
                WHERE er.student_id = ? AND er.exam_id = ?
                ORDER BY er.attempt_number DESC
            '''
            results = self.db.execute_query(query, (student_id, exam_id))
        else:
            # All exams report
            query = '''
                SELECT er.score, er.total_points, er.percentage, er.time_taken,
                       er.submitted_at, e.title, e.subject, er.attempt_number
                FROM exam_results er
                JOIN exams e ON er.exam_id = e.exam_id
                WHERE er.student_id = ?
                ORDER BY er.submitted_at DESC
            '''
            results = self.db.execute_query(query, (student_id,))
        
        # Get student info
        student_query = "SELECT full_name, email FROM users WHERE user_id = ?"
        student_info = self.db.execute_query(student_query, (student_id,))[0]
        
        report = {
            'student_name': student_info[0],
            'student_email': student_info[1],
            'exams': [],
            'summary': {
                'total_exams': len(results),
                'average_score': 0,
                'highest_score': 0,
                'lowest_score': 100 if results else 0
            }
        }
        
        total_percentage = 0
        for row in results:
            exam_data = {
                'score': row[0],
                'total_points': row[1],
                'percentage': row[2],
                'time_taken': row[3],
                'submitted_at': row[4],
                'title': row[5],
                'subject': row[6],
                'attempt_number': row[7]
            }
            report['exams'].append(exam_data)
            
            total_percentage += row[2]
            report['summary']['highest_score'] = max(report['summary']['highest_score'], row[2])
            report['summary']['lowest_score'] = min(report['summary']['lowest_score'], row[2])
        
        if results:
            report['summary']['average_score'] = total_percentage / len(results)
        
        return report
    
    def generate_class_report(self, class_id: int, exam_id: int = None) -> Dict:
        """Generate class performance report"""
        if self.auth.current_user.role not in ['teacher', 'admin']:
            raise PermissionError("Only teachers and admins can view class reports")
        
        if exam_id:
            # Single exam class report
            query = '''
                SELECT u.full_name, er.score, er.total_points, er.percentage,
                       er.submitted_at, er.time_taken
                FROM exam_results er
                JOIN users u ON er.student_id = u.user_id
                JOIN exams e ON er.exam_id = e.exam_id
                WHERE e.class_id = ? AND er.exam_id = ?
                ORDER BY er.percentage DESC
            '''
            results = self.db.execute_query(query, (class_id, exam_id))
        else:
            # All exams class report
            query = '''
                SELECT u.full_name, AVG(er.percentage) as avg_percentage,
                       COUNT(er.result_id) as exam_count
                FROM exam_results er
                JOIN users u ON er.student_id = u.user_id
                JOIN exams e ON er.exam_id = e.exam_id
                WHERE e.class_id = ?
                GROUP BY u.user_id, u.full_name
                ORDER BY avg_percentage DESC
            '''
            results = self.db.execute_query(query, (class_id,))
        
        # Get class info
        class_query = "SELECT class_name, subject FROM classes WHERE class_id = ?"
        class_info = self.db.execute_query(class_query, (class_id,))[0]
        
        report = {
            'class_name': class_info[0],
            'subject': class_info[1],
            'students': [],
            'statistics': {
                'total_students': len(results),
                'average_score': 0,
                'pass_rate': 0,
                'highest_score': 0,
                'lowest_score': 100 if results else 0
            }
        }
        
        total_percentage = 0
        passed_students = 0
        
        for row in results:
            if exam_id:
                student_data = {
                    'name': row[0],
                    'score': row[1],
                    'total_points': row[2],
                    'percentage': row[3],
                    'submitted_at': row[4],
                    'time_taken': row[5]
                }
                percentage = row[3]
            else:
                student_data = {
                    'name': row[0],
                    'average_percentage': row[1],
                    'exam_count': row[2]
                }
                percentage = row[1]
            
            report['students'].append(student_data)
            total_percentage += percentage
            
            if percentage >= 60:  # Assuming 60% is passing grade
                passed_students += 1
            
            report['statistics']['highest_score'] = max(report['statistics']['highest_score'], percentage)
            report['statistics']['lowest_score'] = min(report['statistics']['lowest_score'], percentage)
        
        if results:
            report['statistics']['average_score'] = total_percentage / len(results)
            report['statistics']['pass_rate'] = (passed_students / len(results)) * 100
        
        return report
    
    def export_report_to_csv(self, report_data: Dict, filename: str):
        """Export report to CSV file"""
        if 'students' in report_data:
            # Class report
            df = pd.DataFrame(report_data['students'])
        else:
            # Student report
            df = pd.DataFrame(report_data['exams'])
        
        df.to_csv(filename, index=False)
        return filename
    
    def create_performance_chart(self, student_id: int, save_path: str = "performance_chart.png"):
        """Create performance visualization chart"""
        query = '''
            SELECT e.title, er.percentage, er.submitted_at
            FROM exam_results er
            JOIN exams e ON er.exam_id = e.exam_id
            WHERE er.student_id = ?
            ORDER BY er.submitted_at
        '''
        results = self.db.execute_query(query, (student_id,))
        
        if not results:
            return None
        
        exam_titles = [row[0] for row in results]
        percentages = [row[1] for row in results]
        
        plt.figure(figsize=(12, 6))
        plt.plot(exam_titles, percentages, marker='o', linewidth=2, markersize=8)
        plt.title('Student Performance Over Time', fontsize=16, fontweight='bold')
        plt.xlabel('Exams', fontsize=12)
        plt.ylabel('Percentage Score', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        # Add pass/fail line
        plt.axhline(y=60, color='r', linestyle='--', alpha=0.7, label='Pass Line (60%)')
        plt.legend()
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return save_path

class NotificationManager:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def send_notification(self, user_id: int, title: str, message: str, notification_type: str = "info"):
        """Send notification to user"""
        query = '''
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (?, ?, ?, ?)
        '''
        self.db.execute_update(query, (user_id, title, message, notification_type))
    
    def get_user_notifications(self, user_id: int, unread_only: bool = False) -> List[Dict]:
        """Get notifications for a user"""
        query = '''
            SELECT notification_id, title, message, type, is_read, created_at
            FROM notifications
            WHERE user_id = ?
        '''
        if unread_only:
            query += " AND is_read = 0"
        
        query += " ORDER BY created_at DESC"
        
        results = self.db.execute_query(query, (user_id,))
        
        notifications = []
        for row in results:
            notifications.append({
                'notification_id': row[0],
                'title': row[1],
                'message': row[2],
                'type': row[3],
                'is_read': bool(row[4]),
                'created_at': row[5]
            })
        
        return notifications
    
    def mark_as_read(self, notification_id: int):
        """Mark notification as read"""
        query = "UPDATE notifications SET is_read = 1 WHERE notification_id = ?"
        self.db.execute_update(query, (notification_id,))

class ReExamManager:
    def __init__(self, db_manager: DatabaseManager, auth_manager: AuthenticationManager, 
                 notification_manager: NotificationManager):
        self.db = db_manager
        self.auth = auth_manager
        self.notifications = notification_manager
    
    def request_reexam(self, exam_id: int, reason: str) -> int:
        """Student requests re-examination"""
        if self.auth.current_user.role != 'student':
            raise PermissionError("Only students can request re-exams")
        
        # Check if student has already taken the exam
        check_query = '''
            SELECT COUNT(*) FROM exam_results 
            WHERE exam_id = ? AND student_id = ?
        '''
        result_count = self.db.execute_query(check_query, (exam_id, self.auth.current_user.user_id))[0][0]
        
        if result_count == 0:
            raise ValueError("Cannot request re-exam without taking the original exam")
        
        # Check if there's already a pending request
        pending_query = '''
            SELECT COUNT(*) FROM reexam_requests 
            WHERE exam_id = ? AND student_id = ? AND status = 'pending'
        '''
        pending_count = self.db.execute_query(pending_query, (exam_id, self.auth.current_user.user_id))[0][0]
        
        if pending_count > 0:
            raise ValueError("You already have a pending re-exam request for this exam")
        
        query = '''
            INSERT INTO reexam_requests (exam_id, student_id, reason)
            VALUES (?, ?, ?)
        '''
        conn = sqlite3.connect(self.db.db_name)
        cursor = conn.cursor()
        cursor.execute(query, (exam_id, self.auth.current_user.user_id, reason))
        request_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Get teacher ID for notification
        teacher_query = "SELECT teacher_id FROM exams WHERE exam_id = ?"
        teacher_id = self.db.execute_query(teacher_query, (exam_id,))[0][0]
        
        # Send notification to teacher
        self.notifications.send_notification(
            teacher_id,
            "Re-exam Request",
            f"Student {self.auth.current_user.full_name} has requested a re-exam",
            "request"
        )
        
        self.auth.log_action("request_reexam", f"Requested re-exam for exam {exam_id}")
        return request_id
    
    def review_reexam_request(self, request_id: int, status: str, comments: str = ""):
        """Teacher reviews re-exam request"""
        if self.auth.current_user.role != 'teacher':
            raise PermissionError("Only teachers can review re-exam requests")
        
        query = '''
            UPDATE reexam_requests 
            SET status = ?, reviewed_at = CURRENT_TIMESTAMP, 
                reviewed_by = ?, teacher_comments = ?
            WHERE request_id = ?
        '''
        self.db.execute_update(query, (status, self.auth.current_user.user_id, comments, request_id))
        
        # Get student ID for notification
        student_query = "SELECT student_id FROM reexam_requests WHERE request_id = ?"
        student_id = self.db.execute_query(student_query, (request_id,))[0][0]
        
        # Send notification to student
        self.notifications.send_notification(
            student_id,
            f"Re-exam Request {status.title()}",
            f"Your re-exam request has been {status}. {comments}",
            "response"
        )
        
        self.auth.log_action("review_reexam", f"Reviewed re-exam request {request_id}: {status}")
    
    def get_pending_requests(self, teacher_id: int = None) -> List[Dict]:
        """Get pending re-exam requests for teacher"""
        if teacher_id is None:
            teacher_id = self.auth.current_user.user_id
        
        query = '''
            SELECT rr.request
            SELECT rr.request_id, rr.reason, rr.requested_at, u.full_name as student_name,
                   e.title as exam_title, e.subject
            FROM reexam_requests rr
            JOIN users u ON rr.student_id = u.user_id
            JOIN exams e ON rr.exam_id = e.exam_id
            WHERE e.teacher_id = ? AND rr.status = 'pending'
            ORDER BY rr.requested_at DESC
        '''
        results = self.db.execute_query(query, (teacher_id,))
        
        requests = []
        for row in results:
            requests.append({
                'request_id': row[0],
                'reason': row[1],
                'requested_at': row[2],
                'student_name': row[3],
                'exam_title': row[4],
                'subject': row[5]
            })
        
        return requests

class EvaluXaApp:
    def __init__(self):
        self.db = DatabaseManager()
        self.auth = AuthenticationManager(self.db)
        self.exam_manager = ExamManager(self.db, self.auth)
        self.report_manager = ReportManager(self.db, self.auth)
        self.notifications = NotificationManager(self.db)
        self.reexam_manager = ReExamManager(self.db, self.auth, self.notifications)
        
    def display_banner(self):
        """Display application banner"""
        print("=" * 60)
        print("🎓 EVALUXA - Advanced Exam Management System 🎓")
        print("=" * 60)
        print("Features: Exams • Reports • Analytics • Re-exam Requests")
        print("Roles: Teachers • Students • Parents • Administrators")
        print("=" * 60)
    
    def main_menu(self):
        """Display main menu based on user role"""
        if not self.auth.current_user:
            return self.login_menu()
        
        role = self.auth.current_user.role
        print(f"\n👋 Welcome, {self.auth.current_user.full_name}!")
        print(f"Role: {role.title()} | Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Show unread notifications
        unread_notifications = self.notifications.get_user_notifications(
            self.auth.current_user.user_id, unread_only=True
        )
        if unread_notifications:
            print(f"🔔 You have {len(unread_notifications)} unread notifications")
        
        if role == 'teacher':
            return self.teacher_menu()
        elif role == 'student':
            return self.student_menu()
        elif role == 'parent':
            return self.parent_menu()
        elif role == 'admin':
            return self.admin_menu()
    
    def login_menu(self):
        """Login and registration menu"""
        while True:
            print("\n" + "=" * 40)
            print("🔐 AUTHENTICATION MENU")
            print("=" * 40)
            print("1. Login")
            print("2. Register")
            print("3. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.login()
            elif choice == '2':
                self.register()
            elif choice == '3':
                print("Thank you for using EvaluXa! 👋")
                return False
            else:
                print("❌ Invalid option!")
        
        return True
    
    def login(self):
        """User login"""
        print("\n📝 LOGIN")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        user = self.auth.login(username, password)
        if user:
            print(f"✅ Login successful! Welcome, {user.full_name}")
            time.sleep(1)
        else:
            print("❌ Invalid credentials!")
            time.sleep(1)
    
    def register(self):
        """User registration"""
        print("\n📝 REGISTRATION")
        print("Available roles: student, teacher, parent")
        
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        email = input("Email: ").strip()
        role = input("Role: ").strip().lower()
        full_name = input("Full Name: ").strip()
        phone = input("Phone (optional): ").strip()
        
        if role not in ['student', 'teacher', 'parent']:
            print("❌ Invalid role!")
            return
        
        if self.auth.register_user(username, password, email, role, full_name, phone):
            print("✅ Registration successful!")
            
            # Auto-login after registration
            self.auth.login(username, password)
        else:
            print("❌ Registration failed! Username or email already exists.")
    
    def teacher_menu(self):
        """Teacher dashboard menu"""
        while True:
            print("\n" + "=" * 50)
            print("👨‍🏫 TEACHER DASHBOARD")
            print("=" * 50)
            print("1. 📝 Create New Exam")
            print("2. 📋 Manage Exams")
            print("3. 📊 View Reports")
            print("4. 👥 Manage Classes")
            print("5. 🔄 Re-exam Requests")
            print("6. 🔔 Notifications")
            print("7. 📈 Analytics Dashboard")
            print("8. 📤 Export Reports")
            print("9. ⚙️  Settings")
            print("0. 🚪 Logout")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.create_exam_wizard()
            elif choice == '2':
                self.manage_exams()
            elif choice == '3':
                self.view_teacher_reports()
            elif choice == '4':
                self.manage_classes()
            elif choice == '5':
                self.handle_reexam_requests()
            elif choice == '6':
                self.view_notifications()
            elif choice == '7':
                self.analytics_dashboard()
            elif choice == '8':
                self.export_reports_menu()
            elif choice == '9':
                self.teacher_settings()
            elif choice == '0':
                self.auth.logout()
                break
            else:
                print("❌ Invalid option!")
    
    def student_menu(self):
        """Student dashboard menu"""
        while True:
            print("\n" + "=" * 50)
            print("👨‍🎓 STUDENT DASHBOARD")
            print("=" * 50)
            print("1. 📝 Take Exam")
            print("2. 📊 View My Results")
            print("3. 📈 Performance Analytics")
            print("4. 🔄 Request Re-exam")
            print("5. 🔔 Notifications")
            print("6. 📚 Study Materials")
            print("7. 🎯 Practice Tests")
            print("8. ⚙️  Settings")
            print("0. 🚪 Logout")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.take_exam()
            elif choice == '2':
                self.view_student_results()
            elif choice == '3':
                self.student_analytics()
            elif choice == '4':
                self.request_reexam()
            elif choice == '5':
                self.view_notifications()
            elif choice == '6':
                self.study_materials()
            elif choice == '7':
                self.practice_tests()
            elif choice == '8':
                self.student_settings()
            elif choice == '0':
                self.auth.logout()
                break
            else:
                print("❌ Invalid option!")
    
    def parent_menu(self):
        """Parent dashboard menu"""
        while True:
            print("\n" + "=" * 50)
            print("👨‍👩‍👧‍👦 PARENT DASHBOARD")
            print("=" * 50)
            print("1. 👥 View My Children")
            print("2. 📊 Child Performance Reports")
            print("3. 📈 Progress Analytics")
            print("4. 🔔 Notifications")
            print("5. 📅 Exam Schedule")
            print("6. 💬 Teacher Communication")
            print("7. 📋 Attendance Reports")
            print("8. ⚙️  Settings")
            print("0. 🚪 Logout")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.view_children()
            elif choice == '2':
                self.view_child_reports()
            elif choice == '3':
                self.child_analytics()
            elif choice == '4':
                self.view_notifications()
            elif choice == '5':
                self.exam_schedule()
            elif choice == '6':
                self.teacher_communication()
            elif choice == '7':
                self.attendance_reports()
            elif choice == '8':
                self.parent_settings()
            elif choice == '0':
                self.auth.logout()
                break
            else:
                print("❌ Invalid option!")
    
    def admin_menu(self):
        """Administrator dashboard menu"""
        while True:
            print("\n" + "=" * 50)
            print("⚙️  ADMINISTRATOR DASHBOARD")
            print("=" * 50)
            print("1. 👥 User Management")
            print("2. 🏫 System Overview")
            print("3. 📊 System Reports")
            print("4. 🔧 System Settings")
            print("5. 📋 Audit Logs")
            print("6. 💾 Database Management")
            print("7. 📧 Bulk Notifications")
            print("8. 🔄 System Backup")
            print("0. 🚪 Logout")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.user_management()
            elif choice == '2':
                self.system_overview()
            elif choice == '3':
                self.system_reports()
            elif choice == '4':
                self.system_settings()
            elif choice == '5':
                self.audit_logs()
            elif choice == '6':
                self.database_management()
            elif choice == '7':
                self.bulk_notifications()
            elif choice == '8':
                self.system_backup()
            elif choice == '0':
                self.auth.logout()
                break
            else:
                print("❌ Invalid option!")
    
    def create_exam_wizard(self):
        """Guided exam creation wizard"""
        print("\n" + "=" * 50)
        print("📝 EXAM CREATION WIZARD")
        print("=" * 50)
        
        # Step 1: Basic Information
        print("Step 1: Basic Information")
        title = input("Exam Title: ").strip()
        description = input("Description: ").strip()
        subject = input("Subject: ").strip()
        
        # Step 2: Timing
        print("\nStep 2: Timing")
        duration = int(input("Duration (minutes): "))
        start_time = input("Start Time (YYYY-MM-DD HH:MM): ").strip()
        end_time = input("End Time (YYYY-MM-DD HH:MM): ").strip()
        
        # Step 3: Class Selection
        print("\nStep 3: Class Selection")
        classes = self.get_teacher_classes()
        if not classes:
            print("❌ No classes found! Please create a class first.")
            return
        
        print("Available Classes:")
        for i, cls in enumerate(classes, 1):
            print(f"{i}. {cls['class_name']} - {cls['subject']}")
        
        class_choice = int(input("Select class: ")) - 1
        class_id = classes[class_choice]['class_id']
        
        # Create exam
        try:
            exam_id = self.exam_manager.create_exam(
                title, description, class_id, subject, duration, start_time, end_time
            )
            print(f"✅ Exam created successfully! ID: {exam_id}")
            
            # Step 4: Add Questions
            self.add_questions_wizard(exam_id)
            
        except Exception as e:
            print(f"❌ Error creating exam: {e}")
    
    def add_questions_wizard(self, exam_id: int):
        """Wizard for adding questions to exam"""
        print(f"\n📋 Adding Questions to Exam (ID: {exam_id})")
        
        while True:
            print("\nQuestion Types:")
            print("1. Multiple Choice")
            print("2. True/False")
            print("3. Finish Adding Questions")
            
            choice = input("Select option: ").strip()
            
            if choice == '1':
                self.add_multiple_choice_question(exam_id)
            elif choice == '2':
                self.add_true_false_question(exam_id)
            elif choice == '3':
                break
            else:
                print("❌ Invalid option!")
    
    def add_multiple_choice_question(self, exam_id: int):
        """Add multiple choice question"""
        print("\n➕ Adding Multiple Choice Question")
        
        question_text = input("Question: ").strip()
        
        options = []
        for i in range(4):
            option = input(f"Option {chr(65+i)}: ").strip()
            options.append(option)
        
        correct_answer = input("Correct Answer (A/B/C/D): ").strip().upper()
        points = int(input("Points (default 1): ") or "1")
        difficulty = input("Difficulty (easy/medium/hard): ").strip().lower() or "medium"
        explanation = input("Explanation (optional): ").strip()
        
        try:
            question_id = self.exam_manager.add_question(
                exam_id, question_text, options, correct_answer, points, difficulty, explanation
            )
            print(f"✅ Question added successfully! ID: {question_id}")
        except Exception as e:
            print(f"❌ Error adding question: {e}")
    
    def add_true_false_question(self, exam_id: int):
        """Add true/false question"""
        print("\n➕ Adding True/False Question")
        
        question_text = input("Question: ").strip()
        options = ["True", "False"]
        correct_answer = input("Correct Answer (True/False): ").strip()
        points = int(input("Points (default 1): ") or "1")
        difficulty = input("Difficulty (easy/medium/hard): ").strip().lower() or "medium"
        explanation = input("Explanation (optional): ").strip()
        
        try:
            question_id = self.exam_manager.add_question(
                exam_id, question_text, options, correct_answer, points, difficulty, explanation
            )
            print(f"✅ Question added successfully! ID: {question_id}")
        except Exception as e:
            print(f"❌ Error adding question: {e}")
    
    def take_exam(self):
        """Student takes an exam"""
        print("\n" + "=" * 50)
        print("📝 AVAILABLE EXAMS")
        print("=" * 50)
        
        exams = self.exam_manager.get_student_exams()
        if not exams:
            print("❌ No exams available!")
            return
        
        # Display available exams
        for i, exam in enumerate(exams, 1):
            print(f"{i}. {exam['title']}")
            print(f"   Subject: {exam['subject']} | Duration: {exam['duration_minutes']} min")
            print(f"   Teacher: {exam['teacher_name']} | Class: {exam['class_name']}")
            print(f"   Start: {exam['start_time']} | End: {exam['end_time']}")
            print()
        
        try:
            choice = int(input("Select exam to take: ")) - 1
            selected_exam = exams[choice]
            
            # Check if exam is currently active
            now = datetime.datetime.now()
            start_time = datetime.datetime.strptime(selected_exam['start_time'], '%Y-%m-%d %H:%M:%S')
            end_time = datetime.datetime.strptime(selected_exam['end_time'], '%Y-%m-%d %H:%M:%S')
            
            if now < start_time:
                print("❌ Exam hasn't started yet!")
                return
            elif now > end_time:
                print("❌ Exam has ended!")
                return
            
            self.conduct_exam(selected_exam['exam_id'])
            
        except (ValueError, IndexError):
            print("❌ Invalid selection!")
    
    def conduct_exam(self, exam_id: int):
        """Conduct the actual exam"""
        questions = self.exam_manager.get_exam_questions(exam_id)
        if not questions:
            print("❌ No questions found for this exam!")
            return
        
        print(f"\n🎯 Starting Exam (Total Questions: {len(questions)})")
        print("=" * 50)
        
        answers = {}
        start_time = time.time()
        
        for i, question in enumerate(questions, 1):
            print(f"\nQuestion {i}/{len(questions)} ({question['points']} points)")
            print(f"Difficulty: {question['difficulty'].title()}")
            print("-" * 40)
            print(question['question_text'])
            print()
            
            # Display options
            for j, option in enumerate(question['options']):
                print(f"{chr(65+j)}. {option}")
            
            while True:
                answer = input(f"\nYour answer (A-{chr(64+len(question['options']))}): ").strip().upper()
                if answer in [chr(65+k) for k in range(len(question['options']))]:
                    answers[str(question['question_id'])] = answer
                    break
                else:
                    print("❌ Invalid answer! Please try again.")
        
        end_time = time.time()
        time_taken = int(end_time - start_time)
        
        # Submit exam
        try:
            result_id = self.exam_manager.submit_exam(exam_id, answers)
            print(f"\n✅ Exam submitted successfully!")
            print(f"⏱️  Time taken: {time_taken // 60} minutes {time_taken % 60} seconds")
            
            # Show immediate results if enabled
            self.show_exam_result(result_id)
            
        except Exception as e:
            print(f"❌ Error submitting exam: {e}")
    
    def show_exam_result(self, result_id: int):
        """Show exam result to student"""
        query = '''
            SELECT er.score, er.total_points, er.percentage, e.title
            FROM exam_results er
            JOIN exams e ON er.exam_id = e.exam_id
            WHERE er.result_id = ?
        '''
        result = self.db.execute_query(query, (result_id,))
        
        if result:
            score, total_points, percentage, exam_title = result[0]
            
            print("\n" + "=" * 50)
            print("📊 EXAM RESULT")
            print("=" * 50)
            print(f"Exam: {exam_title}")
            print(f"Score: {score}/{total_points}")
            print(f"Percentage: {percentage:.1f}%")
            
            if percentage >= 90:
                print("🏆 Excellent! Outstanding performance!")
            elif percentage >= 80:
                print("🎉 Great job! Very good performance!")
            elif percentage >= 70:
                print("👍 Good work! Above average performance!")
            elif percentage >= 60:
                print("✅ Passed! Keep improving!")
            else:
                print("📚 Need improvement. Consider requesting a re-exam.")
    
    def view_student_results(self):
        """View student's exam results"""
        print("\n" + "=" * 50)
        print("📊 MY EXAM RESULTS")
        print("=" * 50)
        
        report = self.report_manager.generate_student_report(self.auth.current_user.user_id)
        
        if not report['exams']:
            print("❌ No exam results found!")
            return
        
        print(f"Student: {report['student_name']}")
        print(f"Total Exams: {report['summary']['total_exams']}")
        print(f"Average Score: {report['summary']['average_score']:.1f}%")
        print(f"Highest Score: {report['summary']['highest_score']:.1f}%")
        print(f"Lowest Score: {report['summary']['lowest_score']:.1f}%")
        print("\n" + "-" * 50)
        
        for exam in report['exams']:
            print(f"\n📝 {exam['title']} ({exam['subject']})")
            print(f"   Score: {exam['score']}/{exam['total_points']} ({exam['percentage']:.1f}%)")
            print(f"   Submitted: {exam['submitted_at']}")
            if exam['attempt_number'] > 1:
                print(f"   Attempt: #{exam['attempt_number']}")
    
    def request_reexam(self):
        """Student requests re-examination"""
        print("\n" + "=" * 50)
        print("🔄 REQUEST RE-EXAMINATION")
        print("=" * 50)
        
        # Get student's completed exams
        query = '''
            SELECT DISTINCT e.exam_id, e.title, e.subject, er.percentage
            FROM exams e
            JOIN exam_results er ON e.exam_id = er.exam_id
            WHERE er.student_id = ?
            ORDER BY er.submitted_at DESC
        '''
        results = self.db.execute_query(query, (self.auth.current_user.user_id,))
        
        if not results:
            print("❌ No completed exams found!")
            return
        
        print("Your Completed Exams:")
        for i, (exam_id, title, subject, percentage) in enumerate(results, 1):
            print(f"{i}. {title} ({subject}) - Score: {percentage:.1f}%")
        
        try:
            choice = int(input("\nSelect exam for re-exam request: ")) - 1
            selected_exam_id = results[choice][0]
            
            reason = input("Reason for re-exam request: ").strip()
            
            request_id = self.reexam_manager.request_reexam(selected_exam_id, reason)
            print(f"✅ Re-exam request submitted successfully! Request ID: {request_id}")
            
        except (ValueError, IndexError):
            print("❌ Invalid selection!")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def handle_reexam_requests(self):
        """Teacher handles re-exam requests"""
        print("\n" + "=" * 50)
        print("🔄 RE-EXAM REQUESTS")
        print("=" * 50)
        
        requests = self.reexam_manager.get_pending_requests()
        
        if not requests:
            print("✅ No pending re-exam requests!")
            return
        
        for i, request in enumerate(requests, 1):
            print(f"{i}. Student: {request['student_name']}")
            print(f"   Exam: {request['exam_title']} ({request['subject']})")
            print(f"   Reason: {request['reason']}")
            print(f"   Requested: {request['requested_at']}")
            print()
        
        try:
            choice = int(input("Select request to review: ")) - 1
            selected_request = requests[choice]
            
            print(f"\nReviewing request from {selected_request['student_name']}")
            print("1. Approve")
            print("2. Reject")
            
            decision = input("Decision: ").strip()
            comments = input("Comments (optional): ").strip()
            
            if decision == '1':
                self.reexam_manager.review_reexam_request(
                    selected_request['request_id'], 'approved', comments
                )
                print("✅ Re-exam request approved!")
            elif decision == '2':
                self.reexam_manager.review_reexam_request(
                    selected_request['request_id'], 'rejected', comments
                )
                print("❌ Re-exam request rejected!")
            else:
                print("❌ Invalid decision!")
                
        except (ValueError, IndexError):
            print("❌ Invalid selection!")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def view_notifications(self):
        """View user notifications"""
        print("\n" + "=" * 50)
        print("🔔 NOTIFICATIONS")
        print("=" * 50)
        
        notifications = self.notifications.get_user_notifications(self.auth.current_user.user_id)
        
        if not notifications:
            print("✅ No notifications!")
            return
        
        for notification in notifications:
            status = "📖" if notification['is_read'] else "🔔"
            print(f"{status} {notification['title']}")
            print(f"   {notification['message']}")
            print(f"   {notification['created_at']}")
            print()
            
            if not notification['is_read']:
                self.notifications.mark_as_read(notification['notification_id'])
    
    def get_teacher_classes(self) -> List[Dict]:
        """Get classes for current teacher"""
        query = '''
            SELECT class_id, class_name, subject, description
            FROM classes
            WHERE teacher_id = ?
        '''
        results = self.db.execute_query(query, (self.auth.current_user.user_id,))
        
        classes = []
        for row in results:
            classes.append({
                'class_id': row[0],
                'class_name': row[1],
                'subject': row[2],
                'description': row[3]
            })
        
        return classes
    
    def analytics_dashboard(self):
        """Advanced analytics dashboard"""
        print("\n" + "=" * 50)
        print("📈 ANALYTICS DASHBOARD")
        print("=" * 50)
        
        if self.auth.current_user.role == 'teacher':
            self.teacher_analytics()
        elif self.auth.current_user.role == 'student':
            self.student_analytics()
        elif self.auth.current_user.role == 'parent':
            self.parent_analytics()
    
    def teacher_analytics(self):
        """Teacher analytics"""
        print("Teacher Analytics:")
        
        # Get teacher's exam statistics
        query = '''
            SELECT COUNT(DISTINCT e.exam_id) as total_exams,
                   COUNT(DISTINCT er.student_id) as total_students,
                   AVG(er.percentage) as avg_score,
                   COUNT(er.result_id) as total_attempts
            FROM exams e
            LEFT JOIN exam_results er ON e.exam_id = er.exam_id
            WHERE e.teacher_id = ?
        '''
        stats = self.db.execute_query(query, (self.auth.current_user.user_id,))[0]
        
        print(f"📊 Total Exams Created: {stats[0] or 0}")
        print(f"👥 Total Students: {stats[1] or 0}")
        print(f"📈 Average Score: {stats[2]:.1f}%" if stats[2] else "N/A")
        print(f"📝 Total Exam Attempts: {stats[3] or 0}")
        
        # Subject-wise performance
        subject_query = '''
            SELECT e.subject, AVG(er.percentage) as avg_score, COUNT(er.result_id) as attempts
            FROM exams e
            JOIN exam_results er ON e.exam_id = er.exam_id
            WHERE e.teacher_id = ?
            GROUP BY e.subject
        '''
        subject_stats = self.db.execute_query(subject_query, (self.auth.current_user.user_id,))
        
        if subject_stats:
            print("\n📚 Subject-wise Performance:")
            for subject, avg_score, attempts in subject_stats:
                print(f"   {subject}: {avg_score:.1f}% ({attempts} attempts)")
    
    def student_analytics(self):
        """Student analytics with performance visualization"""
        print("Student Performance Analytics:")
        
        # Generate performance chart
        chart_path = self.report_manager.create_performance_chart(
            self.auth.current_user.user_id, 
            f"student_{self.auth.current_user.user_id}_performance.png"
        )
        
        if chart_path:
            print(f"📊 Performance chart saved as: {chart_path}")
        
        # Get detailed statistics
        report = self.report_manager.generate_student_report(self.auth.current_user.user_id)
        
        if report['exams']:
            print(f"\n📈 Performance Summary:")
            print(f"   Total Exams: {report['summary']['total_exams']}")
            print(f"   Average Score: {report['summary']['average_score']:.1f}%")
            print(f"   Best Performance: {report['summary']['highest_score']:.1f}%")
            print(f"   Improvement Needed: {report['summary']['lowest_score']:.1f}%")
            
            # Subject-wise analysis
            subjects = {}
            for exam in report['exams']:
                subject = exam['subject']
                if subject not in subjects:
                    subjects[subject] = []
                subjects[subject].append(exam['percentage'])
            
            print(f"\n📚 Subject-wise Performance:")
            for subject, scores in subjects.items():
                avg_score = sum(scores) / len(scores)
                print(f"   {subject}: {avg_score:.1f}% ({len(scores)} exams)")
    
    def manage_classes(self):
        """Teacher class management"""
        print("\n" + "=" * 50)
        print("👥 CLASS MANAGEMENT")
        print("=" * 50)
        print("1. Create New Class")
        print("2. View My Classes")
        print("3. Manage Students")
        print("4. Class Reports")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.create_class()
        elif choice == '2':
            self.view_teacher_classes()
        elif choice == '3':
            self.manage_class_students()
        elif choice == '4':
            self.class_reports()
    
    def create_class(self):
        """Create a new class"""
        print("\n➕ CREATE NEW CLASS")
        
        class_name = input("Class Name: ").strip()
        subject = input("Subject: ").strip()
        description = input("Description: ").strip()
        
        query = '''
            INSERT INTO classes (class_name, teacher_id, subject, description)
            VALUES (?, ?, ?, ?)
        '''
        
        try:
            self.db.execute_update(query, (class_name, self.auth.current_user.user_id, subject, description))
            print("✅ Class created successfully!")
        except Exception as e:
            print(f"❌ Error creating class: {e}")
    
    def view_teacher_classes(self):
        """View teacher's classes"""
        classes = self.get_teacher_classes()
        
        if not classes:
            print("❌ No classes found!")
            return
        
        print("\n📚 YOUR CLASSES:")
        for cls in classes:
            print(f"• {cls['class_name']} - {cls['subject']}")
            print(f"  Description: {cls['description']}")
            
            # Get student count
            count_query = "SELECT COUNT(*) FROM class_enrollment WHERE class_id = ?"
            student_count = self.db.execute_query(count_query, (cls['class_id'],))[0][0]
            print(f"  Students: {student_count}")
            print()
    
    def view_child_reports(self):
        """Parent views child performance reports"""
        print("\n" + "=" * 50)
        print("👶 CHILD PERFORMANCE REPORTS")
        print("=" * 50)
        
        # Get parent's children
        children = self.get_parent_children()
        
        if not children:
            print("❌ No children found! Please link your account with your child's account.")
            return
        
        print("Select child:")
        for i, child in enumerate(children, 1):
            print(f"{i}. {child['full_name']} ({child['email']})")
        
        try:
            choice = int(input("Select child: ")) - 1
            selected_child = children[choice]
            
            # Generate comprehensive report
            report = self.report_manager.generate_student_report(selected_child['user_id'])
            
            print(f"\n📊 PERFORMANCE REPORT - {report['student_name']}")
            print("=" * 50)
            
            if report['exams']:
                print(f"📈 Summary Statistics:")
                print(f"   Total Exams: {report['summary']['total_exams']}")
                print(f"   Average Score: {report['summary']['average_score']:.1f}%")
                print(f"   Highest Score: {report['summary']['highest_score']:.1f}%")
                print(f"   Lowest Score: {report['summary']['lowest_score']:.1f}%")
                
                print(f"\n📝 Recent Exam Results:")
                for exam in report['exams'][:5]:  # Show last 5 exams
                    print(f"   • {exam['title']} ({exam['subject']})")
                    print(f"     Score: {exam['score']}/{exam['total_points']} ({exam['percentage']:.1f}%)")
                    print(f"     Date: {exam['submitted_at']}")
                    print()
                
                # Generate performance chart
                chart_path = self.report_manager.create_performance_chart(
                    selected_child['user_id'],
                    f"child_{selected_child['user_id']}_performance.png"
                )
                if chart_path:
                    print(f"📊 Performance chart saved as: {chart_path}")
            else:
                print("❌ No exam results found for this child.")
                
        except (ValueError, IndexError):
            print("❌ Invalid selection!")
    
    def get_parent_children(self) -> List[Dict]:
        """Get children linked to parent account"""
        query = '''
            SELECT u.user_id, u.full_name, u.email, u.username
            FROM users u
            JOIN student_parent sp ON u.user_id = sp.student_id
            WHERE sp.parent_id = ?
        '''
        results = self.db.execute_query(query, (self.auth.current_user.user_id,))
        
        children = []
        for row in results:
            children.append({
                'user_id': row[0],
                'full_name': row[1],
                'email': row[2],
                'username': row[3]
            })
        
        return children
    
    def link_child_account(self):
        """Link parent account with child account"""
        print("\n🔗 LINK CHILD ACCOUNT")
        
        child_username = input("Child's Username: ").strip()
        
        # Verify child exists and is a student
        query = "SELECT user_id, full_name FROM users WHERE username = ? AND role = 'student'"
        result = self.db.execute_query(query, (child_username,))
        
        if not result:
            print("❌ Student account not found!")
            return
        
        child_id, child_name = result[0]
        
        # Check if already linked
        check_query = "SELECT COUNT(*) FROM student_parent WHERE student_id = ? AND parent_id = ?"
        if self.db.execute_query(check_query, (child_id, self.auth.current_user.user_id))[0][0] > 0:
            print("❌ Child account already linked!")
            return
        
        # Link accounts
        link_query = "INSERT INTO student_parent (student_id, parent_id) VALUES (?, ?)"
        self.db.execute_update(link_query, (child_id, self.auth.current_user.user_id))
        
        print(f"✅ Successfully linked with {child_name}'s account!")
    
    def export_reports_menu(self):
        """Export reports menu"""
        print("\n" + "=" * 50)
        print("📤 EXPORT REPORTS")
        print("=" * 50)
        print("1. Export Student Results (CSV)")
        print("2. Export Class Performance (CSV)")
        print("3. Export Exam Analytics (CSV)")
        print("4. Generate PDF Report")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.export_student_results()
        elif choice == '2':
            self.export_class_performance()
        elif choice == '3':
            self.export_exam_analytics()
        elif choice == '4':
            self.generate_pdf_report()
    
    def export_student_results(self):
        """Export student results to CSV"""
        if self.auth.current_user.role == 'student':
            # Student exports their own results
            report = self.report_manager.generate_student_report(self.auth.current_user.user_id)
            filename = f"student_{self.auth.current_user.user_id}_results.csv"
        else:
            # Teacher/Parent selects student
            print("Enter student ID or username:")
            student_input = input().strip()
            
            # Try to find student
            if student_input.isdigit():
                student_id = int(student_input)
            else:
                query = "SELECT user_id FROM users WHERE username = ? AND role = 'student'"
                result = self.db.execute_query(query, (student_input,))
                if not result:
                    print("❌ Student not found!")
                    return
                student_id = result[0][0]
            
            report = self.report_manager.generate_student_report(student_id)
            filename = f"student_{student_id}_results.csv"
        
        try:
            self.report_manager.export_report_to_csv(report, filename)
            print(f"✅ Report exported to {filename}")
        except Exception as e:
            print(f"❌ Export failed: {e}")
    
    def practice_tests(self):
        """Practice tests for students"""
        print("\n" + "=" * 50)
        print("🎯 PRACTICE TESTS")
        print("=" * 50)
        print("1. Subject-wise Practice")
        print("2. Difficulty-based Practice")
        print("3. Timed Practice Tests")
        print("4. Review Mistakes")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.subject_practice()
        elif choice == '2':
            self.difficulty_practice()
        elif choice == '3':
            self.timed_practice()
        elif choice == '4':
            self.review_mistakes()
    
    def subject_practice(self):
        """Subject-wise practice"""
        # Get available subjects from student's classes
        query = '''
            SELECT DISTINCT e.subject
            FROM exams e
            JOIN classes c ON e.class_id = c.class_id
            JOIN class_enrollment ce ON c.class_id = ce.class_id
            WHERE ce.student_id = ?
        '''
        subjects = self.db.execute_query(query, (self.auth.current_user.user_id,))
        
        if not subjects:
            print("❌ No subjects available for practice!")
            return
        
        print("Available Subjects:")
        for i, (subject,) in enumerate(subjects, 1):
            print(f"{i}. {subject}")
        
        try:
            choice = int(input("Select subject: ")) - 1
            selected_subject = subjects[choice][0]
            
            # Get random questions from this subject
            self.generate_practice_test(subject=selected_subject)
            
        except (ValueError, IndexError):
            print("❌ Invalid selection!")
    
    def generate_practice_test(self, subject=None, difficulty=None, question_count=5):
        """Generate a practice test"""
        query = '''
            SELECT q.question_text, q.options, q.correct_answer, q.explanation, q.difficulty
            FROM questions q
            JOIN exams e ON q.exam_id = e.exam_id
            JOIN classes c ON e.class_id = c.class_id
            JOIN class_enrollment ce ON c.class_id = ce.class_id
            WHERE ce.student_id = ?
        '''
        params = [self.auth.current_user.user_id]
        
        if subject:
            query += " AND e.subject = ?"
            params.append(subject)
        
        if difficulty:
            query += " AND q.difficulty = ?"
            params.append(difficulty)
        
        query += f" ORDER BY RANDOM() LIMIT {question_count}"
        
        questions = self.db.execute_query(query, tuple(params))
        
        if not questions:
            print("❌ No practice questions available!")
            return
        
        print(f"\n🎯 PRACTICE TEST ({len(questions)} questions)")
        print("=" * 50)
        
        score = 0
        for i, (question_text, options_json, correct_answer, explanation, difficulty) in enumerate(questions, 1):
            options = json.loads(options_json)
            
            print(f"\nQuestion {i}/{len(questions)} [Difficulty: {difficulty.title()}]")
            print("-" * 40)
            print(question_text)
            print()
            
            for j, option in enumerate(options):
                print(f"{chr(65+j)}. {option}")
            
            answer = input(f"\nYour answer: ").strip().upper()
            
            if answer == correct_answer:
                print("✅ Correct!")
                score += 1
            else:
                print(f"❌ Incorrect! Correct answer: {correct_answer}")
            
            if explanation:
                print(f"💡 Explanation: {explanation}")
            
            print()
        
        percentage = (score / len(questions)) * 100
        print(f"🎯 Practice Test Complete!")
        print(f"Score: {score}/{len(questions)} ({percentage:.1f}%)")
        
        if percentage >= 80:
            print("🏆 Excellent! You're well prepared!")
        elif percentage >= 60:
            print("👍 Good job! Keep practicing!")
        else:
            print("📚 More practice needed. Review the topics!")
    
    def system_overview(self):
        """System overview for administrators"""
        print("\n" + "=" * 50)
        print("🏫 SYSTEM OVERVIEW")
        print("=" * 50)
        
        # Get system statistics
        stats = {}
        
        # User statistics
        user_query = "SELECT role, COUNT(*) FROM users GROUP BY role"
        user_stats = self.db.execute_query(user_query)
        stats['users'] = dict(user_stats)
        
        # Exam statistics
        exam_query = "SELECT COUNT(*) FROM exams"
        stats['total_exams'] = self.db.execute_query(exam_query)[0][0]
        
        # Active exams
        active_exam_query = "SELECT COUNT(*) FROM exams WHERE is_active = 1"
        stats['active_exams'] = self.db.execute_query(active_exam_query)[0][0]
        
        # Total exam attempts
        attempts_query = "SELECT COUNT(*) FROM exam_results"
        stats['total_attempts'] = self.db.execute_query(attempts_query)[0][0]
        
        # Average system performance
        avg_query = "SELECT AVG(percentage) FROM exam_results"
        avg_result = self.db.execute_query(avg_query)[0][0]
        stats['avg_performance'] = avg_result if avg_result else 0
        
        # Display statistics
        print("👥 User Statistics:")
        for role, count in stats['users'].items():
            print(f"   {role.title()}s: {count}")
        
        print(f"\n📊 Exam Statistics:")
        print(f"   Total Exams: {stats['total_exams']}")
        print(f"   Active Exams: {stats['active_exams']}")
        print(f"   Total Attempts: {stats['total_attempts']}")
        print(f"   Average Performance: {stats['avg_performance']:.1f}%")
        
        # Recent activity
        print(f"\n📈 Recent Activity:")
        recent_query = '''
            SELECT action, COUNT(*) as count
            FROM system_logs
            WHERE timestamp >= datetime('now', '-7 days')
            GROUP BY action
            ORDER BY count DESC
            LIMIT 5
        '''
        recent_activity = self.db.execute_query(recent_query)
        
        for action, count in recent_activity:
            print(f"   {action}: {count} times")
    
    def user_management(self):
        """User management for administrators"""
        print("\n" + "=" * 50)
        print("👥 USER MANAGEMENT")
        print("=" * 50)
        print("1. View All Users")
        print("2. Create User Account")
        print("3. Deactivate User")
        print("4. Reset User Password")
        print("5. User Activity Report")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.view_all_users()
        elif choice == '2':
            self.create_user_account()
        elif choice == '3':
            self.deactivate_user()
        elif choice == '4':
            self.reset_user_password()
        elif choice == '5':
            self.user_activity_report()
    
    def view_all_users(self):
        """View all system users"""
        query = '''
            SELECT user_id, username, email, role, full_name, created_at, is_active
            FROM users
            ORDER BY created_at DESC
        '''
        users = self.db.execute_query(query)
        
        print(f"\n👥 ALL USERS ({len(users)} total)")
        print("-" * 80)
        print(f"{'ID':<5} {'Username':<15} {'Role':<10} {'Name':<20} {'Status':<8}")
        print("-" * 80)
        
        for user in users:
            user_id, username, email, role, full_name, created_at, is_active = user
            status = "Active" if is_active else "Inactive"
            print(f"{user_id:<5} {username:<15} {role:<10} {full_name:<20} {status:<8}")
    
    def bulk_notifications(self):
        """Send bulk notifications"""
        print("\n" + "=" * 50)
        print("📧 BULK NOTIFICATIONS")
        print("=" * 50)
        print("1. Notify All Students")
        print("2. Notify All Teachers")
        print("3. Notify All Parents")
        print("4. Notify All Users")
        print("5. Custom User Selection")
        
        choice = input("Select option: ").strip()
        
        title = input("Notification Title: ").strip()
        message = input("Notification Message: ").strip()
        notification_type = input("Type (info/warning/urgent): ").strip() or "info"
        
        if choice == '1':
            self.send_role_notification('student', title, message, notification_type)
        elif choice == '2':
            self.send_role_notification('teacher', title, message, notification_type)
        elif choice == '3':
            self.send_role_notification('parent', title, message, notification_type)
        elif choice == '4':
            self.send_all_notification(title, message, notification_type)
        elif choice == '5':
            self.custom_notification(title, message, notification_type)
    
    def send_role_notification(self, role: str, title: str, message: str, notification_type: str):
        """Send notification to all users of a specific role"""
        query = "SELECT user_id FROM users WHERE role = ? AND is_active = 1"
        users = self.db.execute_query(query, (role,))
        
        count = 0
        for (user_id,) in users:
            self.notifications.send_notification(user_id, title, message, notification_type)
            count += 1
        
        print(f"✅ Notification sent to {count} {role}s!")
    
    def audit_logs(self):
        """View system audit logs"""
        print("\n" + "=" * 50)
        print("📋 SYSTEM AUDIT LOGS")
        print("=" * 50)
        
        # Get recent logs
        query = '''
            SELECT sl.timestamp, u.username, sl.action, sl.details
            FROM system_logs sl
            JOIN users u ON sl.user_id = u.user_id
            ORDER BY sl.timestamp DESC
            LIMIT 50
        '''
        logs = self.db.execute_query(query)
        
        print(f"Recent Activity (Last 50 entries):")
        print("-" * 80)
        print(f"{'Time':<20} {'User':<15} {'Action':<15} {'Details':<30}")
        print("-" * 80)
        
        for timestamp, username, action, details in logs:
            # Truncate long details
            details = details[:27] + "..." if len(details) > 30 else details
            print(f"{timestamp:<20} {username:<15} {action:<15} {details:<30}")
    
    def teacher_settings(self):
        """Teacher account settings"""
        print("\n" + "=" * 50)
        print("⚙️  TEACHER SETTINGS")
        print("=" * 50)
        print("1. Update Profile")
        print("2. Change Password")
        print("3. Notification Preferences")
        print("4. Export Data")
        print("5. Account Statistics")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.update_profile()
        elif choice == '2':
            self.change_password()
        elif choice == '3':
            self.notification_preferences()
        elif choice == '4':
            self.export_teacher_data()
        elif choice == '5':
            self.account_statistics()
    
    def student_settings(self):
        """Student account settings"""
        print("\n" + "=" * 50)
        print("⚙️  STUDENT SETTINGS")
        print("=" * 50)
        print("1. Update Profile")
        print("2. Change Password")
        print("3. Study Preferences")
        print("4. Performance Goals")
        print("5. Link Parent Account")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.update_profile()
        elif choice == '2':
            self.change_password()
        elif choice == '3':
            self.study_preferences()
        elif choice == '4':
            self.performance_goals()
        elif choice == '5':
            self.link_parent_account()
    
    def parent_settings(self):
        """Parent account settings"""
        print("\n" + "=" * 50)
        print("⚙️  PARENT SETTINGS")
        print("=" * 50)
        print("1. Update Profile")
        print("2. Change Password")
        print("3. Link Child Account")
        print("4. Notification Preferences")
        print("5. Communication Settings")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.update_profile()
        elif choice == '2':
            self.change_password()
        elif choice == '3':
            self.link_child_account()
        elif choice == '4':
            self.notification_preferences()
        elif choice == '5':
            self.communication_settings()
    
    def update_profile(self):
        """Update user profile"""
        print("\n✏️  UPDATE PROFILE")
        
        current_user = self.auth.current_user
        print(f"Current Name: {current_user.full_name}")
        print(f"Current Email: {current_user.email}")
        
        new_name = input("New Full Name (press Enter to keep current): ").strip()
        new_email = input("New Email (press Enter to keep current): ").strip()
        new_phone = input("New Phone (press Enter to keep current): ").strip()
        
        updates = []
        params = []
        
        if new_name:
            updates.append("full_name = ?")
            params.append(new_name)
        
        if new_email:
            updates.append("email = ?")
            params.append(new_email)
        
        if new_phone:
            updates.append("phone = ?")
            params.append(new_phone)
        
        if updates:
            query = f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?"
            params.append(current_user.user_id)
            
            try:
                self.db.execute_update(query, tuple(params))
                print("✅ Profile updated successfully!")
                self.auth.log_action("update_profile", "Profile information updated")
            except Exception as e:
                print(f"❌ Error updating profile: {e}")
        else:
            print("ℹ️  No changes made.")
    
    def change_password(self):
        """Change user password"""
        print("\n🔒 CHANGE PASSWORD")
        
        current_password = input("Current Password: ").strip()
        new_password = input("New Password: ").strip()
        confirm_password = input("Confirm New Password: ").strip()
        
        if new_password != confirm_password:
            print("❌ Passwords don't match!")
            return
        
        # Verify current password
        current_hash = self.db.hash_password(current_password)
        query = "SELECT COUNT(*) FROM users WHERE user_id = ? AND password_hash = ?"
        if self.db.execute_query(query, (self.auth.current_user.user_id, current_hash))[0][0] == 0:
            print("❌ Current password is incorrect!")
            return
        
        # Update password
        new_hash = self.db.hash_password(new_password)
        update_query = "UPDATE users SET password_hash = ? WHERE user_id = ?"
        
        try:
            self.db.execute_update(update_query, (new_hash, self.auth.current_user.user_id))
            print("✅ Password changed successfully!")
            self.auth.log_action("change_password", "Password updated")
        except Exception as e:
            print(f"❌ Error changing password: {e}")
    
    def run(self):
        """Main application loop"""
        self.display_banner()
        
        try:
            while True:
                if not self.main_menu():
                    break
        except KeyboardInterrupt:
            print("\n\n👋 Thank you for using EvaluXa!")
        except Exception as e:
            print(f"\n❌ An error occurred: {e}")
            print("Please contact system administrator.")

# Additional utility functions and features

def create_sample_data(app: EvaluXaApp):
    """Create sample data for demonstration"""
    print("Creating sample data...")
    
    # Create sample users
    sample_users = [
        ("teacher1", "pass123", "teacher1@evaluxa.com", "teacher", "Dr. John Smith", "123-456-7890"),
        ("student1", "pass123", "student1@evaluxa.com", "student", "Alice Johnson", "123-456-7891"),
        ("student2", "pass123", "student2@evaluxa.com", "student", "Bob Wilson", "123-456-7892"),
        ("parent1", "pass123", "parent1@evaluxa.com", "parent", "Mary Johnson", "123-456-7893"),
    ]
    
    for username, password, email, role, full_name, phone in sample_users:
        app.auth.register_user(username, password, email, role, full_name, phone)
    
    print("✅ Sample data created!")
    print("Sample login credentials:")
    print("Teacher: teacher1 / pass123")
    print("Student: student1 / pass123")
    print("Parent: parent1 / pass123")
    print("Admin: admin / admin123")

def main():
    """Main function to run EvaluXa"""
    app = EvaluXaApp()
    
    # Check if this is first run
    user_count_query = "SELECT COUNT(*) FROM users WHERE role != 'admin'"
    user_count = app.db.execute_query(user_count_query)[0][0]
    
    if user_count == 0:
        print("🎉 Welcome to EvaluXa! This appears to be your first time running the application.")
        create_sample = input("Would you like to create sample data for testing? (y/n): ").strip().lower()
        if create_sample == 'y':
            create_sample_data(app)
    
    app.run()

if __name__ == "__main__":
    main()
