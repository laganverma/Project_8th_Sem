import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, message):
    sender_email = "trackersincident@gmail.com"
    receiver_email = "anya.mathur18@gmail.com"
    password = "mdtp hujj cvqq wztw"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)

# Example condition
condition = True

if condition:
    subject = "Alert: Condition is True"
    message = "The condition you are monitoring is now true. And the mail is being sent now the work is to create the the file condition"
    send_email(subject, message)
    print("Email sent successfully.")
else:
    print("Condition is not true, no email sent.")
