import imaplib
import email
from email.header import decode_header

def connect_to_email(username, password, imap_server="imap.gmail.com"):
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, password)
        return mail
    except Exception as e:
        print(f"Error connecting to email: {e}")
        return None

def fetch_emails(mail):
    mail.select("inbox")
    _, messages = mail.search(None, "ALL")
    for num in messages[0].split():
        _, msg = mail.fetch(num, "(RFC822)")
        raw_email = email.message_from_bytes(msg[0][1])
        analyze_email(raw_email)

def analyze_email(raw_email):
    subject = decode_header(raw_email["Subject"])[0][0]
    sender = raw_email.get("From")
    print(f"Subject: {subject}")
    print(f"Sender: {sender}")
    if raw_email.is_multipart():
        for part in raw_email.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode()
                print(f"Body: {body}")
                detect_phishing(subject, sender, body)

def detect_phishing(subject, sender, body):
    phishing_keywords = ["password", "urgent", "account verification"]
    if any(keyword in body.lower() for keyword in phishing_keywords):
        print("Potential phishing email detected!")
        print(f"Sender: {sender}, Subject: {subject}")

if __name__ == "__main__":
    username = "your_email@example.com"
    password = "your_password"
    mail = connect_to_email(username, password)
    if mail:
        fetch_emails(mail)