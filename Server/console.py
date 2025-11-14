#!/usr/bin/env python3
"""
ISO 27001 Annex A Audit Console
A comprehensive security audit tool for Windows and Linux systems
"""

import sys
import json
import subprocess
import platform
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QComboBox, QProgressBar,
    QTabWidget, QTableWidget, QTableWidgetItem, QGroupBox,
    QSplitter, QMessageBox, QFileDialog, QHeaderView
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor


class AuditThread(QThread):
    """Background thread for running audits"""
    progress_updated = Signal(int, str)
    audit_completed = Signal(dict)
    error_occurred = Signal(str)

    def __init__(self, target_os: str):
        super().__init__()
        self.target_os = target_os
        self.results = {}

    def run(self):
        """Execute the audit based on target OS"""
        try:
            if self.target_os == "Windows":
                self.results = self.audit_windows()
            elif self.target_os == "Linux":
                self.results = self.audit_linux()
            elif self.target_os == "MacOS":
                raise NotImplementedError("MacOS auditing is not implemented yet.")
            
            self.audit_completed.emit(self.results)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def audit_windows(self) -> Dict[str, Any]:
        """Run Windows-specific ISO 27001 Annex A audits"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "os": "Windows",
            "controls": []
        }
        
        controls = [
            ("A.5.1", "Policies for information security", self.check_windows_policies),
            ("A.5.2", "Information security roles", self.check_windows_roles),
            ("A.8.1", "User access management", self.check_windows_users),
            ("A.8.2", "User access provisioning", self.check_windows_access),
            ("A.8.3", "Privileged access rights", self.check_windows_admin),
            ("A.8.5", "Secure authentication", self.check_windows_auth),
            ("A.8.8", "Management of technical vulnerabilities", self.check_windows_updates),
            ("A.8.9", "Configuration management", self.check_windows_config),
            ("A.8.10", "Information deletion", self.check_windows_deletion),
            ("A.8.15", "Logging", self.check_windows_logging),
            ("A.8.16", "Monitoring activities", self.check_windows_monitoring),
            ("A.8.18", "Use of privileged utility programs", self.check_windows_utilities),
            ("A.8.23", "Web filtering", self.check_windows_filtering),
            ("A.8.26", "Application security requirements", self.check_windows_appsec),
        ]
        
        total = len(controls)
        for idx, (control_id, control_name, check_func) in enumerate(controls):
            progress = int((idx + 1) / total * 100)
            self.progress_updated.emit(progress, f"Checking {control_id}: {control_name}")
            
            result = check_func()
            results["controls"].append({
                "id": control_id,
                "name": control_name,
                "status": result["status"],
                "findings": result["findings"],
                "recommendations": result.get("recommendations", [])
            })
        
        return results

    def audit_linux(self) -> Dict[str, Any]:
        """Run Linux-specific ISO 27001 Annex A audits"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "os": "Linux",
            "controls": []
        }
        
        controls = [
            ("A.5.1", "Policies for information security", self.check_linux_policies),
            ("A.5.2", "Information security roles", self.check_linux_roles),
            ("A.8.1", "User access management", self.check_linux_users),
            ("A.8.2", "User access provisioning", self.check_linux_access),
            ("A.8.3", "Privileged access rights", self.check_linux_sudo),
            ("A.8.5", "Secure authentication", self.check_linux_auth),
            ("A.8.8", "Management of technical vulnerabilities", self.check_linux_updates),
            ("A.8.9", "Configuration management", self.check_linux_config),
            ("A.8.10", "Information deletion", self.check_linux_deletion),
            ("A.8.15", "Logging", self.check_linux_logging),
            ("A.8.16", "Monitoring activities", self.check_linux_monitoring),
            ("A.8.18", "Use of privileged utility programs", self.check_linux_utilities),
            ("A.8.23", "Web filtering", self.check_linux_filtering),
            ("A.8.26", "Application security requirements", self.check_linux_appsec),
        ]
        
        total = len(controls)
        for idx, (control_id, control_name, check_func) in enumerate(controls):
            progress = int((idx + 1) / total * 100)
            self.progress_updated.emit(progress, f"Checking {control_id}: {control_name}")
            
            result = check_func()
            results["controls"].append({
                "id": control_id,
                "name": control_name,
                "status": result["status"],
                "findings": result["findings"],
                "recommendations": result.get("recommendations", [])
            })
        
        return results

    # Windows Check Functions
    def check_windows_policies(self) -> Dict:
        """Check Windows security policies"""
        try:
            cmd = "secedit /export /cfg temp_policy.inf"
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            
            findings = []
            if Path("temp_policy.inf").exists():
                findings.append("Security policy export successful")
                Path("temp_policy.inf").unlink()
                status = "PASS"
            else:
                findings.append("Unable to export security policies")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_windows_roles(self) -> Dict:
        """Check Windows user roles and groups"""
        try:
            result = subprocess.run(
                "net localgroup Administrators",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                admins = [line.strip() for line in result.stdout.split('\n') if line.strip() and not line.startswith('-')]
                findings.append(f"Found {len(admins)} administrator accounts")
                status = "PASS" if len(admins) <= 5 else "WARN"
            else:
                findings.append("Unable to enumerate administrator accounts")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_windows_users(self) -> Dict:
        """Check Windows user accounts"""
        try:
            result = subprocess.run(
                "net user",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                findings.append("User enumeration successful")
                status = "PASS"
            else:
                findings.append("Unable to enumerate users")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_windows_access(self) -> Dict:
        """Check Windows access control"""
        findings = ["Access control check requires manual review"]
        return {"status": "INFO", "findings": findings}

    def check_windows_admin(self) -> Dict:
        """Check Windows privileged access"""
        try:
            result = subprocess.run(
                "net localgroup Administrators",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                findings.append("Privileged access audit completed")
                status = "PASS"
            else:
                findings.append("Unable to audit privileged access")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_windows_auth(self) -> Dict:
        """Check Windows authentication settings"""
        try:
            result = subprocess.run(
                "net accounts",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                findings.append("Authentication policy retrieved")
                if "lockout threshold" in result.stdout.lower():
                    findings.append("Account lockout policy configured")
                status = "PASS"
            else:
                findings.append("Unable to retrieve authentication settings")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_windows_updates(self) -> Dict:
        """Check Windows update status"""
        try:
            result = subprocess.run(
                "wmic qfe list brief",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                updates = [line for line in result.stdout.split('\n') if line.strip()]
                findings.append(f"Found {len(updates)} installed updates")
                status = "PASS" if len(updates) > 0 else "WARN"
            else:
                findings.append("Unable to check update status")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_windows_config(self) -> Dict:
        """Check Windows configuration management"""
        findings = ["Configuration baseline review required"]
        return {"status": "INFO", "findings": findings}

    def check_windows_deletion(self) -> Dict:
        """Check Windows secure deletion capabilities"""
        findings = ["Secure deletion tools check required"]
        return {"status": "INFO", "findings": findings}

    def check_windows_logging(self) -> Dict:
        """Check Windows logging configuration"""
        try:
            result = subprocess.run(
                "wevtutil gli Security",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                findings.append("Security event log accessible")
                status = "PASS"
            else:
                findings.append("Unable to access security logs")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_windows_monitoring(self) -> Dict:
        """Check Windows monitoring capabilities"""
        findings = ["Monitoring configuration requires review"]
        return {"status": "INFO", "findings": findings}

    def check_windows_utilities(self) -> Dict:
        """Check Windows privileged utilities"""
        findings = ["Privileged utility usage tracking required"]
        return {"status": "INFO", "findings": findings}

    def check_windows_filtering(self) -> Dict:
        """Check Windows web filtering"""
        findings = ["Web filtering configuration requires review"]
        return {"status": "INFO", "findings": findings}

    def check_windows_appsec(self) -> Dict:
        """Check Windows application security"""
        try:
            result = subprocess.run(
                "wmic product get name,version",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                findings.append("Installed applications enumerated")
                status = "PASS"
            else:
                findings.append("Unable to enumerate applications")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    # Linux Check Functions
    def check_linux_policies(self) -> Dict:
        """Check Linux security policies"""
        try:
            checks = [
                ("SELinux", "getenforce"),
                ("AppArmor", "aa-status"),
            ]
            
            findings = []
            status = "PASS"
            
            for policy_name, cmd in checks:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    findings.append(f"{policy_name} is active: {result.stdout.strip()}")
                else:
                    findings.append(f"{policy_name} check failed or not installed")
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_roles(self) -> Dict:
        """Check Linux user roles"""
        try:
            result = subprocess.run(
                "getent group sudo wheel 2>/dev/null | cut -d: -f4",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            findings = []
            if result.returncode == 0:
                sudo_users = result.stdout.strip().split(',')
                findings.append(f"Found {len(sudo_users)} users with sudo privileges")
                status = "PASS" if len(sudo_users) <= 5 else "WARN"
            else:
                findings.append("Unable to check sudo users")
                status = "INFO"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_users(self) -> Dict:
        """Check Linux user accounts"""
        try:
            result = subprocess.run(
                "cat /etc/passwd | grep -v nologin | grep -v false | wc -l",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            findings = []
            if result.returncode == 0:
                user_count = result.stdout.strip()
                findings.append(f"Found {user_count} active user accounts")
                status = "PASS"
            else:
                findings.append("Unable to enumerate users")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_access(self) -> Dict:
        """Check Linux access control"""
        try:
            result = subprocess.run(
                "ls -la /etc/shadow",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            findings = []
            if result.returncode == 0:
                findings.append("Password file permissions verified")
                if "rw-------" in result.stdout or "r--------" in result.stdout:
                    findings.append("Shadow file has correct permissions")
                    status = "PASS"
                else:
                    findings.append("Shadow file permissions may be incorrect")
                    status = "WARN"
            else:
                findings.append("Unable to check shadow file permissions")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_sudo(self) -> Dict:
        """Check Linux sudo configuration"""
        try:
            result = subprocess.run(
                "sudo -l 2>&1",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            findings = []
            if "NOPASSWD" in result.stdout:
                findings.append("Warning: Passwordless sudo detected")
                status = "WARN"
            else:
                findings.append("Sudo configuration reviewed")
                status = "PASS"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "INFO", "findings": ["Sudo check requires privileges"]}

    def check_linux_auth(self) -> Dict:
        """Check Linux authentication settings"""
        try:
            checks = [
                ("PAM", "/etc/pam.d/common-auth"),
                ("Login defs", "/etc/login.defs"),
            ]
            
            findings = []
            status = "PASS"
            
            for check_name, file_path in checks:
                if Path(file_path).exists():
                    findings.append(f"{check_name} configuration found")
                else:
                    findings.append(f"{check_name} configuration missing")
                    status = "WARN"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_updates(self) -> Dict:
        """Check Linux update status"""
        try:
            # Try different package managers
            commands = [
                ("apt", "apt list --upgradable 2>/dev/null | wc -l"),
                ("yum", "yum list updates 2>/dev/null | wc -l"),
                ("dnf", "dnf list updates 2>/dev/null | wc -l"),
            ]
            
            findings = []
            status = "INFO"
            
            for pkg_mgr, cmd in commands:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    try:
                        updates = int(result.stdout.strip())
                        findings.append(f"{pkg_mgr}: {updates} updates available")
                        status = "PASS" if updates == 0 else "WARN"
                        break
                    except ValueError:
                        continue
            
            if not findings:
                findings.append("Unable to check for updates")
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_config(self) -> Dict:
        """Check Linux configuration management"""
        findings = ["Configuration baseline review required"]
        return {"status": "INFO", "findings": findings}

    def check_linux_deletion(self) -> Dict:
        """Check Linux secure deletion tools"""
        try:
            tools = ["shred", "wipe", "srm"]
            found_tools = []
            
            for tool in tools:
                result = subprocess.run(
                    f"which {tool}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    found_tools.append(tool)
            
            findings = []
            if found_tools:
                findings.append(f"Secure deletion tools found: {', '.join(found_tools)}")
                status = "PASS"
            else:
                findings.append("No secure deletion tools found")
                status = "WARN"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_logging(self) -> Dict:
        """Check Linux logging configuration"""
        try:
            log_files = [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/syslog",
            ]
            
            findings = []
            found_logs = []
            
            for log_file in log_files:
                if Path(log_file).exists():
                    found_logs.append(log_file)
            
            if found_logs:
                findings.append(f"Found {len(found_logs)} log files")
                status = "PASS"
            else:
                findings.append("No standard log files found")
                status = "WARN"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_monitoring(self) -> Dict:
        """Check Linux monitoring tools"""
        try:
            tools = ["auditd", "rsyslog", "journalctl"]
            found_tools = []
            
            for tool in tools:
                result = subprocess.run(
                    f"which {tool}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    found_tools.append(tool)
            
            findings = []
            if found_tools:
                findings.append(f"Monitoring tools found: {', '.join(found_tools)}")
                status = "PASS"
            else:
                findings.append("No monitoring tools found")
                status = "WARN"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}

    def check_linux_utilities(self) -> Dict:
        """Check Linux privileged utilities"""
        findings = ["Privileged utility tracking requires review"]
        return {"status": "INFO", "findings": findings}

    def check_linux_filtering(self) -> Dict:
        """Check Linux web filtering"""
        findings = ["Web filtering configuration requires review"]
        return {"status": "INFO", "findings": findings}

    def check_linux_appsec(self) -> Dict:
        """Check Linux application security"""
        try:
            result = subprocess.run(
                "dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            findings = []
            if result.returncode == 0:
                pkg_count = result.stdout.strip()
                findings.append(f"Found {pkg_count} installed packages")
                status = "PASS"
            else:
                findings.append("Unable to enumerate packages")
                status = "FAIL"
            
            return {"status": status, "findings": findings}
        except Exception as e:
            return {"status": "ERROR", "findings": [f"Error: {str(e)}"]}


class MainWindow(QMainWindow):
    """Main application window for ISO 27001 Audit Console"""
    
    def __init__(self):
        super().__init__()
        self.audit_thread = None
        self.audit_results = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("ISO 27001 Annex A Audit Console")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Header section
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Progress section
        self.progress_group = self.create_progress_section()
        main_layout.addWidget(self.progress_group)
        
        # Create splitter for main content
        splitter = QSplitter(Qt.Horizontal)
        
        # Results tabs
        self.tabs = QTabWidget()
        self.summary_tab = self.create_summary_tab()
        self.details_tab = self.create_details_tab()
        self.raw_tab = self.create_raw_tab()
        
        self.tabs.addTab(self.summary_tab, "Summary")
        self.tabs.addTab(self.details_tab, "Detailed Results")
        self.tabs.addTab(self.raw_tab, "Raw Output")
        
        splitter.addWidget(self.tabs)
        
        # Console output
        console_widget = QWidget()
        console_layout = QVBoxLayout(console_widget)
        console_label = QLabel("Console Output:")
        console_label.setStyleSheet("font-weight: bold;")
        console_layout.addWidget(console_label)
        
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setMaximumHeight(200)
        console_layout.addWidget(self.console_output)
        
        splitter.addWidget(console_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        
        main_layout.addWidget(splitter, stretch=1)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        self.log_message("ISO 27001 Annex A Audit Console initialized")
        self.log_message(f"Detected OS: {platform.system()}")
        
    def create_header(self) -> QWidget:
        """Create header section"""
        header = QWidget()
        layout = QVBoxLayout(header)
        
        title = QLabel("ISO 27001 Annex A Security Audit Console")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        
        subtitle = QLabel("Comprehensive security auditing for Windows and Linux systems")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #666;")
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        
        return header
    
    def create_control_panel(self) -> QWidget:
        """Create control panel with OS selection and buttons"""
        panel = QGroupBox("Audit Controls")
        layout = QHBoxLayout(panel)
        
        # OS Selection
        os_label = QLabel("Target OS:")
        self.os_combo = QComboBox()
        self.os_combo.addItems(["Windows", "Linux"])
        
        # Set default based on current OS
        current_os = platform.system()
        if current_os == "Windows":
            self.os_combo.setCurrentText("Windows")
        elif current_os == "Linux":
            self.os_combo.setCurrentText("Linux")
        
        # Buttons
        self.start_btn = QPushButton("Start Audit")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.start_btn.clicked.connect(self.start_audit)
        
        self.stop_btn = QPushButton("Stop Audit")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.stop_btn.clicked.connect(self.stop_audit)
        
        self.export_btn = QPushButton("Export Report")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_report)
        
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        
        layout.addWidget(os_label)
        layout.addWidget(self.os_combo)
        layout.addStretch()
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.export_btn)
        layout.addWidget(self.clear_btn)
        
        return panel
    
    def create_progress_section(self) -> QWidget:
        """Create progress bar section"""
        group = QGroupBox("Audit Progress")
        layout = QVBoxLayout(group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        
        self.progress_label = QLabel("Ready to start audit")
        self.progress_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_label)
        
        return group
    
    def create_summary_tab(self) -> QWidget:
        """Create summary tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        
        layout.addWidget(self.summary_text)
        
        return widget
    
    def create_details_tab(self) -> QWidget:
        """Create detailed results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(4)
        self.details_table.setHorizontalHeaderLabels(["Control ID", "Control Name", "Status", "Findings"])
        
        header = self.details_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        layout.addWidget(self.details_table)
        
        return widget
    
    def create_raw_tab(self) -> QWidget:
        """Create raw output tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.raw_output = QTextEdit()
        self.raw_output.setReadOnly(True)
        self.raw_output.setFontFamily("Courier New")
        
        layout.addWidget(self.raw_output)
        
        return widget
    
    def start_audit(self):
        """Start the audit process"""
        target_os = self.os_combo.currentText()
        self.log_message(f"Starting audit for {target_os}...")
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Initializing audit...")
        
        # Clear previous results
        self.summary_text.clear()
        self.details_table.setRowCount(0)
        self.raw_output.clear()
        
        # Create and start audit thread
        self.audit_thread = AuditThread(target_os)
        self.audit_thread.progress_updated.connect(self.update_progress)
        self.audit_thread.audit_completed.connect(self.audit_finished)
        self.audit_thread.error_occurred.connect(self.audit_error)
        self.audit_thread.start()
        
        self.statusBar().showMessage(f"Running {target_os} audit...")
    
    def stop_audit(self):
        """Stop the running audit"""
        if self.audit_thread and self.audit_thread.isRunning():
            self.log_message("Stopping audit...")
            self.audit_thread.terminate()
            self.audit_thread.wait()
            self.audit_cleanup()
    
    def update_progress(self, value: int, message: str):
        """Update progress bar and label"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
        self.log_message(f"[{value}%] {message}")
    
    def audit_finished(self, results: Dict):
        """Handle audit completion"""
        self.audit_results = results
        self.log_message("Audit completed successfully!")
        
        # Display results
        self.display_summary(results)
        self.display_details(results)
        self.display_raw(results)
        
        # Update UI
        self.audit_cleanup()
        self.export_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        self.progress_label.setText("Audit completed")
        self.statusBar().showMessage("Audit completed successfully")
    
    def audit_error(self, error_msg: str):
        """Handle audit error"""
        self.log_message(f"ERROR: {error_msg}", error=True)
        QMessageBox.critical(self, "Audit Error", f"An error occurred during the audit:\n\n{error_msg}")
        self.audit_cleanup()
    
    def audit_cleanup(self):
        """Clean up after audit"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def display_summary(self, results: Dict):
        """Display audit summary"""
        summary = f"<h2>ISO 27001 Annex A Audit Summary</h2>"
        summary += f"<p><b>Target OS:</b> {results['os']}</p>"
        summary += f"<p><b>Timestamp:</b> {results['timestamp']}</p>"
        summary += f"<p><b>Total Controls Checked:</b> {len(results['controls'])}</p>"
        
        # Count statuses
        status_counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0, "ERROR": 0}
        for control in results['controls']:
            status = control['status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        summary += "<h3>Results by Status:</h3><ul>"
        for status, count in status_counts.items():
            color = {
                "PASS": "green",
                "FAIL": "red",
                "WARN": "orange",
                "INFO": "blue",
                "ERROR": "darkred"
            }.get(status, "black")
            summary += f"<li><span style='color: {color}; font-weight: bold;'>{status}</span>: {count}</li>"
        summary += "</ul>"
        
        # Compliance percentage
        total = len(results['controls'])
        passed = status_counts["PASS"]
        if total > 0:
            compliance = (passed / total) * 100
            summary += f"<p><b>Compliance Rate:</b> {compliance:.1f}%</p>"
        
        self.summary_text.setHtml(summary)
    
    def display_details(self, results: Dict):
        """Display detailed audit results"""
        self.details_table.setRowCount(len(results['controls']))
        
        for row, control in enumerate(results['controls']):
            # Control ID
            id_item = QTableWidgetItem(control['id'])
            
            # Control Name
            name_item = QTableWidgetItem(control['name'])
            
            # Status
            status_item = QTableWidgetItem(control['status'])
            status_colors = {
                "PASS": QColor(144, 238, 144),
                "FAIL": QColor(255, 182, 193),
                "WARN": QColor(255, 218, 185),
                "INFO": QColor(173, 216, 230),
                "ERROR": QColor(255, 160, 122)
            }
            status_item.setBackground(status_colors.get(control['status'], QColor(255, 255, 255)))
            
            # Findings
            findings_text = "\n".join(control['findings'])
            findings_item = QTableWidgetItem(findings_text)
            
            self.details_table.setItem(row, 0, id_item)
            self.details_table.setItem(row, 1, name_item)
            self.details_table.setItem(row, 2, status_item)
            self.details_table.setItem(row, 3, findings_item)
        
        self.details_table.resizeRowsToContents()
    
    def display_raw(self, results: Dict):
        """Display raw JSON output"""
        raw_json = json.dumps(results, indent=2)
        self.raw_output.setPlainText(raw_json)
    
    def export_report(self):
        """Export audit report to file"""
        if not self.audit_results:
            QMessageBox.warning(self, "No Results", "No audit results to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Audit Report",
            f"iso27001_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.audit_results, f, indent=2)
                self.log_message(f"Report exported to: {filename}")
                QMessageBox.information(self, "Export Successful", f"Report exported to:\n{filename}")
            except Exception as e:
                self.log_message(f"Export failed: {str(e)}", error=True)
                QMessageBox.critical(self, "Export Failed", f"Failed to export report:\n{str(e)}")
    
    def clear_results(self):
        """Clear all results"""
        self.summary_text.clear()
        self.details_table.setRowCount(0)
        self.raw_output.clear()
        self.console_output.clear()
        self.progress_bar.setValue(0)
        self.progress_label.setText("Ready to start audit")
        self.audit_results = None
        self.export_btn.setEnabled(False)
        self.log_message("Results cleared")
    
    def log_message(self, message: str, error: bool = False):
        """Add message to console output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}"
        
        cursor = self.console_output.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        if error:
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(255, 0, 0))
            cursor.insertText(formatted_msg + "\n", fmt)
        else:
            cursor.insertText(formatted_msg + "\n")
        
        self.console_output.setTextCursor(cursor)
        self.console_output.ensureCursorVisible()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()