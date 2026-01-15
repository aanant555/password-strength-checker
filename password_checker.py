#!/usr/bin/env python3
"""
Password Strength Checker - Cybersecurity Tool
Analyzes password strength and provides security recommendations
"""

import re
import string
import hashlib
from getpass import getpass


class PasswordStrengthChecker:
    def __init__(self):
        # Common weak passwords (top 20)
        self.common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password1', '12345678', '111111', '123123', 'admin',
            'letmein', 'welcome', 'monkey', '1234567890', 'password123',
            'qwerty123', '1q2w3e4r', 'passw0rd', 'iloveyou', 'dragon'
        ]
        
        # Leaked password hashes (SHA-256 of common passwords)
        self.leaked_hashes = set([
            hashlib.sha256(pwd.encode()).hexdigest() 
            for pwd in self.common_passwords
        ])

    def check_length(self, password):
        """
        Check password length
        Returns: (score, message)
        """
        length = len(password)
        
        if length < 8:
            return 0, "❌ Too short (minimum 8 characters required)"
        elif length < 12:
            return 1, "⚠️  Acceptable length (12+ recommended)"
        elif length < 16:
            return 2, "✅ Good length"
        else:
            return 3, "✅ Excellent length"

    def check_complexity(self, password):
        """
        Check character variety (uppercase, lowercase, digits, special)
        Returns: (score, details)
        """
        score = 0
        details = []
        
        if re.search(r'[a-z]', password):
            score += 1
            details.append("✅ Contains lowercase")
        else:
            details.append("❌ Missing lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
            details.append("✅ Contains uppercase")
        else:
            details.append("❌ Missing uppercase letters")
        
        if re.search(r'\d', password):
            score += 1
            details.append("✅ Contains numbers")
        else:
            details.append("❌ Missing numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
            details.append("✅ Contains special characters")
        else:
            details.append("❌ Missing special characters")
        
        return score, details

    def check_common_patterns(self, password):
        """
        Check for common weak patterns
        Returns: (deductions, warnings)
        """
        deductions = 0
        warnings = []
        
        # Check if password is in common list
        if password.lower() in self.common_passwords:
            deductions += 3
            warnings.append("⚠️  CRITICAL: This is a commonly used password!")
        
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            deductions += 1
            warnings.append("⚠️  Contains sequential numbers")
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            deductions += 1
            warnings.append("⚠️  Contains sequential letters")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            deductions += 1
            warnings.append("⚠️  Contains repeated characters (aaa, 111, etc.)")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '1qaz', '2wsx']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                deductions += 1
                warnings.append("⚠️  Contains keyboard pattern")
                break
        
        return deductions, warnings

    def check_leaked(self, password):
        """
        Check if password hash exists in leaked database
        Returns: (is_leaked, message)
        """
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if pwd_hash in self.leaked_hashes:
            return True, "⚠️  CRITICAL: This password has been found in data breaches!"
        return False, "✅ Not found in common breach databases"

    def calculate_entropy(self, password):
        """
        Calculate password entropy (bits of randomness)
        """
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        import math
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)

    def analyze_password(self, password):
        """
        Comprehensive password analysis
        Returns: strength score and detailed report
        """
        total_score = 0
        report = []
        
        # 1. Length check (max 3 points)
        length_score, length_msg = self.check_length(password)
        total_score += length_score
        report.append(f"\n📏 Length Analysis: {length_msg}")
        
        # 2. Complexity check (max 4 points)
        complexity_score, complexity_details = self.check_complexity(password)
        total_score += complexity_score
        report.append(f"\n🔤 Complexity Analysis:")
        for detail in complexity_details:
            report.append(f"   {detail}")
        
        # 3. Pattern check (deductions)
        pattern_deductions, pattern_warnings = self.check_common_patterns(password)
        total_score -= pattern_deductions
        if pattern_warnings:
            report.append(f"\n⚠️  Pattern Warnings:")
            for warning in pattern_warnings:
                report.append(f"   {warning}")
        
        # 4. Leaked check
        is_leaked, leaked_msg = self.check_leaked(password)
        report.append(f"\n🔍 Breach Check: {leaked_msg}")
        if is_leaked:
            total_score -= 5
        
        # 5. Entropy calculation
        entropy = self.calculate_entropy(password)
        report.append(f"\n🎲 Entropy: {entropy} bits")
        if entropy < 30:
            report.append("   ⚠️  Low entropy - easily crackable")
        elif entropy < 50:
            report.append("   ⚠️  Moderate entropy - could be cracked")
        else:
            report.append("   ✅ High entropy - strong randomness")
        
        # Final score normalization
        total_score = max(0, min(10, total_score))
        
        return total_score, report

    def get_strength_rating(self, score):
        """
        Convert numerical score to strength rating
        """
        if score <= 2:
            return "🔴 VERY WEAK - Change immediately!", "red"
        elif score <= 4:
            return "🟠 WEAK - Not recommended", "orange"
        elif score <= 6:
            return "🟡 MODERATE - Could be stronger", "yellow"
        elif score <= 8:
            return "🟢 STRONG - Good password", "green"
        else:
            return "🟢 VERY STRONG - Excellent password", "green"

    def generate_recommendations(self, password, score):
        """
        Generate security recommendations
        """
        recommendations = []
        
        if score < 8:
            recommendations.append("\n💡 Recommendations to Improve:")
            
            if len(password) < 12:
                recommendations.append("   • Increase length to at least 12-16 characters")
            
            if not re.search(r'[A-Z]', password):
                recommendations.append("   • Add uppercase letters (A-Z)")
            
            if not re.search(r'[a-z]', password):
                recommendations.append("   • Add lowercase letters (a-z)")
            
            if not re.search(r'\d', password):
                recommendations.append("   • Add numbers (0-9)")
            
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                recommendations.append("   • Add special characters (!@#$%^&*)")
        
        # General best practices
        recommendations.append("\n🛡️  Security Best Practices:")
        recommendations.append("   • Use a unique password for each account")
        recommendations.append("   • Enable Two-Factor Authentication (2FA)")
        recommendations.append("   • Use a password manager")
        recommendations.append("   • Change passwords regularly (every 3-6 months)")
        recommendations.append("   • Never share passwords or write them down")
        
        return recommendations


def print_banner():
    """
    Print tool banner
    """
    print("\n" + "="*60)
    print("🔐 PASSWORD STRENGTH CHECKER - Cybersecurity Tool")
    print("="*60)
    print("Analyze password security and get recommendations")
    print("="*60 + "\n")


def main():
    """
    Main function
    """
    print_banner()
    
    checker = PasswordStrengthChecker()
    
    while True:
        print("\nOptions:")
        print("1. Check a password")
        print("2. Exit")
        
        choice = input("\nEnter your choice (1-2): ").strip()
        
        if choice == '1':
            # Get password securely (hidden input)
            password = getpass("\nEnter password to check (input hidden): ")
            
            if not password:
                print("\n❌ Password cannot be empty!")
                continue
            
            print("\n" + "-"*60)
            print("📊 ANALYSIS REPORT")
            print("-"*60)
            
            # Analyze password
            score, report = checker.analyze_password(password)
            
            # Print detailed report
            for line in report:
                print(line)
            
            # Print final rating
            strength_rating, color = checker.get_strength_rating(score)
            print(f"\n" + "="*60)
            print(f"Final Score: {score}/10")
            print(f"Strength Rating: {strength_rating}")
            print("="*60)
            
            # Print recommendations
            recommendations = checker.generate_recommendations(password, score)
            for rec in recommendations:
                print(rec)
            
            print("\n" + "-"*60)
        
        elif choice == '2':
            print("\n👋 Thank you for using Password Strength Checker!")
            print("Stay secure! 🔐\n")
            break
        
        else:
            print("\n❌ Invalid choice. Please enter 1 or 2.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user.")
        print("Stay secure! 🔐\n")
