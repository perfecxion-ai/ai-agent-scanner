# Exact Commands to Set Up GitHub Repository 🚀

**Run these commands in order to create your private GitHub repository**

Author: **scthornton**

## 📍 Prerequisites

1. Create the GitHub repository first:
   - Go to: https://github.com/new
   - Repository name: `ai-agent-scanner`
   - Make it **Private**
   - Do NOT initialize with README, .gitignore, or license
   - Click "Create repository"

## 🔧 Commands to Run

Copy and paste these commands one by one:

### 1. Navigate to Project Directory
```bash
cd /home/plucky/Developer/projects/personal/ai-agent-scanner/ai-agent-scanner
```

### 2. Initialize Git Repository
```bash
git init
```

### 3. Configure Git User (Use Your Email)
```bash
git config user.name "scthornton"
git config user.email "your-email@example.com"  # Replace with your actual email
```

### 4. Add All Files
```bash
git add .
```

### 5. Create Initial Commit
```bash
git commit -m "Initial commit: AI Agent Scanner v1.0

Enterprise-grade AI security assessment platform with comprehensive
vulnerability testing and risk assessment capabilities.

Features:
- AI agent discovery (network, code, cloud)
- Security testing (prompt injection, access control, data privacy)
- Risk assessment with CVSS-inspired scoring
- Web dashboard and CLI interfaces
- OWASP LLM Top 10 coverage

🤖 Built by scthornton
🔒 Defensive cybersecurity tool for AI infrastructure security

Co-Authored-By: Claude <noreply@anthropic.com>"
```

### 6. Add GitHub Remote
```bash
git remote add origin https://github.com/scthornton/ai-agent-scanner.git
```

### 7. Set Main Branch
```bash
git branch -M main
```

### 8. Push to GitHub
```bash
git push -u origin main
```

## ✅ Verification Commands

After pushing, verify everything worked:

```bash
# Check remote configuration
git remote -v

# Check branch status
git branch -a

# Check last commit
git log --oneline -1
```

## 🔐 SSH Setup (Optional but Recommended)

If you prefer SSH authentication for better security:

### Generate SSH Key (if you don't have one)
```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

### Add to SSH Agent
```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

### Copy Public Key
```bash
cat ~/.ssh/id_ed25519.pub
```

### Add to GitHub
1. Copy the output from the command above
2. Go to GitHub: Settings > SSH and GPG keys > New SSH key
3. Paste the key and save

### Update Remote to Use SSH
```bash
git remote set-url origin git@github.com:scthornton/ai-agent-scanner.git
```

### Test SSH Connection
```bash
ssh -T git@github.com
```

## 🎯 Future Development Workflow

For future changes:

```bash
# Make your changes, then:
git add .
git commit -m "Your descriptive commit message

🤖 Built by scthornton

Co-Authored-By: Claude <noreply@anthropic.com>"
git push
```

## 🚨 If You Encounter Issues

### Authentication Error
If you get authentication errors:
1. Use SSH setup above, OR
2. Use GitHub Personal Access Token instead of password
3. Go to GitHub: Settings > Developer settings > Personal access tokens > Generate new token

### Repository Already Exists Error
If the repository already has content:
```bash
git pull origin main --allow-unrelated-histories
```

### Permission Denied
Make sure you have access to the repository and are using the correct username.

## ✨ Success!

After running these commands successfully, your AI Agent Scanner will be:

✅ Hosted on GitHub as a private repository  
✅ Properly attributed to you (scthornton)  
✅ Ready for ongoing development  
✅ Secured with appropriate .gitignore rules  
✅ Documented with comprehensive README  

**Your repository URL**: https://github.com/scthornton/ai-agent-scanner

---

**🎉 Congratulations!** Your AI security assessment platform is now professionally hosted on GitHub!