# 🔐 Password Strength Checker

**A powerful cybersecurity tool to analyze password strength and provide security recommendations.**

Built with Python for cybersecurity awareness and password security education.

---

## 🎯 Features

✅ **Comprehensive Analysis**
- Length validation (8-16+ characters)
- Character complexity check (uppercase, lowercase, numbers, special chars)
- Pattern detection (sequential, repeated, keyboard patterns)
- Common password detection
- Leaked password database check
- Entropy calculation (randomness measurement)

✅ **Security Recommendations**
- Personalized improvement suggestions
- Best practices for password security
- 2FA and password manager recommendations

✅ **User-Friendly**
- Interactive CLI interface
- Hidden password input (secure)
- Color-coded strength ratings
- Detailed analysis reports

---

## 🛠️ Tech Stack

- **Language:** Python 3.x
- **Libraries:** 
  - `re` - Regular expressions for pattern matching
  - `hashlib` - SHA-256 hashing for breach detection
  - `getpass` - Secure password input
  - `math` - Entropy calculations

---

## 📁 Project Structure

```
password-strength-checker/
│
├── password_checker.py    # Main Python script
└── README.md              # Documentation
```

---

## 🚀 Installation & Usage

### Prerequisites
- Python 3.6 or higher installed
- Terminal/Command Prompt access

### Step 1: Clone the Repository
```bash
git clone https://github.com/anant11819/password-strength-checker.git
cd password-strength-checker
```

### Step 2: Run the Tool
```bash
python password_checker.py
```

### Step 3: Analyze Your Password
1. Select option `1` to check a password
2. Enter your password (input will be hidden)
3. View detailed analysis report
4. Get personalized recommendations

---

## 📊 How It Works

### 1. **Length Check** (0-3 points)
- < 8 characters: Very Weak
- 8-11 characters: Acceptable
- 12-15 characters: Good
- 16+ characters: Excellent

### 2. **Complexity Check** (0-4 points)
Checks for presence of:
- Lowercase letters (a-z)
- Uppercase letters (A-Z)
- Numbers (0-9)
- Special characters (!@#$%^&*)

### 3. **Pattern Detection** (Deductions)
- Common passwords (password, 123456, etc.)
- Sequential characters (abc, 123, xyz)
- Repeated characters (aaa, 111)
- Keyboard patterns (qwerty, asdfgh)

### 4. **Breach Check**
Compares password hash against known leaked passwords

### 5. **Entropy Calculation**
Measures randomness in bits:
- < 30 bits: Easily crackable
- 30-50 bits: Moderate
- 50+ bits: Strong

### Final Score: 0-10
- 🔴 0-2: VERY WEAK
- 🟠 3-4: WEAK
- 🟡 5-6: MODERATE
- 🟢 7-8: STRONG
- 🟢 9-10: VERY STRONG

---

## 📝 Example Output

```
============================================================
🔐 PASSWORD STRENGTH CHECKER - Cybersecurity Tool
============================================================
Analyze password security and get recommendations
============================================================

Options:
1. Check a password
2. Exit

Enter your choice (1-2): 1

Enter password to check (input hidden): ********

------------------------------------------------------------
📊 ANALYSIS REPORT
------------------------------------------------------------

📏 Length Analysis: ✅ Good length

🔤 Complexity Analysis:
   ✅ Contains lowercase
   ✅ Contains uppercase
   ✅ Contains numbers
   ✅ Contains special characters

🔍 Breach Check: ✅ Not found in common breach databases

🎲 Entropy: 68.4 bits
   ✅ High entropy - strong randomness

============================================================
Final Score: 9/10
Strength Rating: 🟢 VERY STRONG - Excellent password
============================================================

🛡️  Security Best Practices:
   • Use a unique password for each account
   • Enable Two-Factor Authentication (2FA)
   • Use a password manager
   • Change passwords regularly (every 3-6 months)
   • Never share passwords or write them down

------------------------------------------------------------
```

---

## 💡 Use Cases

✅ **Personal Use**
- Check strength of existing passwords
- Create stronger passwords
- Learn about password security

✅ **Educational**
- Cybersecurity awareness training
- Password security workshops
- Information security courses

✅ **Professional**
- Security audits
- Password policy compliance
- User awareness programs

---

## ⚠️ Security Note

- This tool runs **locally** on your machine
- Passwords are **never stored** or transmitted
- Analysis happens in real-time in memory
- No external API calls or network requests
- Your passwords remain **100% private**

---

## 🛡️ Password Best Practices

1. **Length Matters** - Minimum 12 characters, 16+ is better
2. **Mix Character Types** - Use all 4 types (upper, lower, number, special)
3. **Avoid Patterns** - No sequential or repeated characters
4. **Unique Passwords** - Different password for each account
5. **Use Password Managers** - Tools like Bitwarden, 1Password, LastPass
6. **Enable 2FA** - Two-Factor Authentication adds extra security
7. **Regular Updates** - Change passwords every 3-6 months
8. **Never Share** - Don't share or write down passwords

---

## 🔧 Future Enhancements

- [ ] Have I Been Pwned API integration
- [ ] Password generator with custom rules
- [ ] GUI version with Tkinter/PyQt
- [ ] Multi-language support
- [ ] Export reports to PDF
- [ ] Batch password analysis
- [ ] Password policy templates

---

## 📚 Learning Resources

- [OWASP Password Guidelines](https://owasp.org/www-community/password-special-characters)
- [NIST Password Standards](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [Password Strength Calculator](https://www.security.org/how-secure-is-my-password/)

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for improvements:
1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📄 License

This project is open source and available under the MIT License.

---

## 👤 Author

**Anant**
- GitHub: [@anant11819](https://github.com/anant11819)
- Portfolio: [anant11819.github.io/portfolio-website](https://anant11819.github.io/portfolio-website/)

---

## 👍 Acknowledgments

- Inspired by cybersecurity best practices
- Built for educational and awareness purposes
- Thanks to the open-source security community

---

⭐ **If you find this tool helpful, please star this repository!** ⭐

Stay secure! 🔐
