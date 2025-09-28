import cv2
import numpy as np
from deepface import DeepFace
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
import time
from datetime import datetime
import threading
import json
from pathlib import Path
import logging
import requests
import requests


class SmartIntruderDetector:
    def __init__(self):
        self.owner_images = []
        self.owner_email = None
        self.smtp_config = {}
        self.email_enabled = False
        self.detection_active = False
        self.last_alert_time = 0
        self.alert_cooldown = 30
        self.confidence_threshold = 0.45
        self.detection_logs = []
        self.sms_enabled = False
        self.phone_number = None


        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_system.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        Path("owner_images").mkdir(exist_ok=True)
        Path("intruder_alerts").mkdir(exist_ok=True)
        Path("logs").mkdir(exist_ok=True)

    def setup_owner(self):
        print("\n🔧 Loading authorized owners' images...")
        owner_dir = Path("owner_images")
        images = list(owner_dir.glob("*.jpg")) + list(owner_dir.glob("*.png"))

        if not images:
            print("❌ No owner images found in 'owner_images/' folder.")
            return False
        self.owner_images = [str(img) for img in images]
        print(f"✅ Loaded {len(self.owner_images)} authorized owners.")
        self.owner_email = input("Enter owner's email to receive alerts: ")
        return True
    def send_sms_alert(self, detection_type="intruder"):
        if not self.sms_enabled or not self.phone_number:
            return False
        try:
            response = requests.post('https://textbelt.com/text', {
                'phone': self.phone_number,
                'message': f"🚨 ALERT: {detection_type.upper()} detected at your home! Check email for image.",
                'key': 'textbelt',  # For one free SMS per day; upgrade for paid use
            })
            if response.json().get('success'):
                self.logger.info(f"SMS alert sent to {self.phone_number}")
                return True
            else:
                self.logger.warning(f"SMS failed: {response.json()}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to send SMS alert: {e}")
            return False


    def setup_alerts(self):
        print("\n📧 Setting up email alerts...")
        email_choice = input("Enable email alerts? (y/n): ").lower() == 'y'
        if not email_choice:
            print("❌ Email alerts must be enabled to proceed!")
            return False
        if self.setup_email():
            self.email_enabled = True
            sms_choice = input("Enable SMS alerts? (y/n): ").lower() == 'y'
            if sms_choice:
                self.sms_enabled = True
                self.phone_number = input("Enter phone number (with country code, e.g., +91XXXXXXXXXX): ")

            return True
        else:
            print("❌ Email setup failed")
            return False

    def setup_email(self):
        print("\n📧 Setting up email...")
        smtp_server = input("Enter SMTP server (e.g., smtp.gmail.com): ")
        smtp_port = int(input("Enter SMTP port (e.g., 587): "))
        sender_email = input("Enter sender email: ")
        sender_password = input("Enter sender password/app password: ")
        self.smtp_config = {
            'server': smtp_server,
            'port': smtp_port,
            'email': sender_email,
            'password': sender_password
        }
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.quit()
            print("✅ Email configuration successful!")
            return True
        except Exception as e:
            print(f"❌ Email configuration failed: {e}")
            return False

    def verify_face(self, frame):
        try:
            temp_path = "temp_frame.jpg"
            cv2.imwrite(temp_path, frame)

            for owner_image in self.owner_images:
                result = DeepFace.verify(
                    img1_path=owner_image,
                    img2_path=temp_path,
                    model_name="Facenet",
                    enforce_detection=False
                )
                if result['distance'] <= self.confidence_threshold:
                    os.remove(temp_path)
                    return True, result['distance']

            os.remove(temp_path)
            return False, 1.0
        except Exception as e:
            self.logger.error(f"Face verification error: {e}")
            return False, 1.0

    def send_alerts(self, frame, detection_type="intruder"):
        email_result = self.send_alert_email(frame, detection_type) if self.email_enabled else False
        sms_result = self.send_sms_alert(detection_type) if self.sms_enabled else False
        return email_result or sms_result

    def send_alert_email(self, frame, detection_type="intruder"):
        if not self.email_enabled:
            return False
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            alert_image_path = f"intruder_alerts/alert_{timestamp}.jpg"
            cv2.imwrite(alert_image_path, frame)

            msg = MIMEMultipart()
            msg['From'] = self.smtp_config['email']
            msg['To'] = self.owner_email
            msg['Subject'] = f"🚨 SECURITY ALERT: {detection_type.upper()} DETECTED"

            body = f"""
            🚨 SECURITY ALERT 🚨

            Detection Type: {detection_type.upper()}
            Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            Location: Home Security System

            An unauthorized person has been detected by your security system.
            Please check the attached image and take appropriate action.

            This is an automated message from your Smart Intruder Detector System.
            """
            msg.attach(MIMEText(body, 'plain'))

            with open(alert_image_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename= "alert_{timestamp}.jpg"')
                msg.attach(part)

            server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'])
            server.starttls()
            server.login(self.smtp_config['email'], self.smtp_config['password'])
            server.sendmail(self.smtp_config['email'], self.owner_email, msg.as_string())
            server.quit()

            self.logger.info(f"Alert email sent successfully for {detection_type}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send alert email: {e}")
            return False

    def log_detection(self, detection_type, confidence=0.0):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': detection_type,
            'confidence': confidence,
            'status': 'alert_sent' if detection_type == 'intruder' else 'authorized'
        }
        self.detection_logs.append(log_entry)
        with open('logs/detection_logs.json', 'w') as f:
            json.dump(self.detection_logs, f, indent=2)

    def start_detection(self):
        print("\n🔍 Starting intruder detection...")
        print("Press 'q' to quit, 's' to pause/resume, 'a' to adjust sensitivity")
        print("✅ System is configured to recognize all authorized family members.")
        print("🚨 Anyone else will be flagged as an intruder.")

        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("❌ Error: Could not open camera")
            return

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        cap.set(cv2.CAP_PROP_FPS, 30)

        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        detection_status = "ACTIVE"
        fps_counter = 0
        fps_start_time = time.time()

        while True:
            ret, frame = cap.read()
            if not ret:
                break
            frame = cv2.flip(frame, 1)
            original_frame = frame.copy()
            fps_counter += 1
            if time.time() - fps_start_time >= 1.0:
                fps = fps_counter / (time.time() - fps_start_time)
                fps_counter = 0
                fps_start_time = time.time()
            else:
                fps = 0

            if self.detection_active:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.3, 5)
                for (x, y, w, h) in faces:
                    face_region = frame[y:y+h, x:x+w]
                    if face_region.size > 0:
                        is_owner, distance = self.verify_face(face_region)
                        current_time = time.time()
                        if is_owner:
                            cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
                            cv2.putText(frame, f"AUTHORIZED (conf: {1-distance:.2f})",
                                        (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
                            detection_status = "AUTHORIZED"
                            self.log_detection("owner", 1-distance)
                        else:
                            cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 0, 255), 2)
                            cv2.putText(frame, f"INTRUDER! (conf: {distance:.2f})",
                                        (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
                            detection_status = "INTRUDER DETECTED!"
                            if current_time - self.last_alert_time > self.alert_cooldown:
                                threading.Thread(target=self.send_alerts, args=(original_frame, "intruder")).start()
                                self.last_alert_time = current_time
                                self.log_detection("intruder", distance)

            cv2.putText(frame, f"Status: {detection_status}", (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            cv2.putText(frame, f"Detection: {'ON' if self.detection_active else 'OFF'}",
                        (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.7,
                        (0, 255, 0) if self.detection_active else (0, 0, 255), 2)
            cv2.putText(frame, f"FPS: {fps:.1f}", (10, 90),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 0), 2)
            cv2.putText(frame, f"Threshold: {self.confidence_threshold:.2f}",
                        (10, 120), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 0), 2)
            cv2.putText(frame, "Controls: Q=Quit, S=Start/Stop, A=Adjust",
                        (10, frame.shape[0]-20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
            cv2.imshow('Smart Intruder Detector', frame)

            key = cv2.waitKey(1) & 0xFF
            if key == ord('q'):
                break
            elif key == ord('s'):
                self.detection_active = not self.detection_active
                print(f"Detection {'activated' if self.detection_active else 'deactivated'}")
            elif key == ord('a'):
                new_threshold = input("\nEnter new confidence threshold (0.0-1.0): ")
                try:
                    self.confidence_threshold = float(new_threshold)
                    print(f"Threshold updated to {self.confidence_threshold}")
                except ValueError:
                    print("Invalid threshold value")
        time.sleep(1)
        cap.release()
        cv2.destroyAllWindows()
        print("🔒 Detection stopped")

    def run(self):
        print("🏠 Smart Intruder Detector System")
        print("=" * 40)
        if not self.setup_owner():
            print("❌ Owner setup failed")
            return
        if not self.setup_alerts():
            print("❌ Alert setup failed")
            return
        self.detection_active = True
        self.start_detection()
        print("\n📊 Detection Summary:")
        print(f"Total logs: {len(self.detection_logs)}")
        owner_detections = sum(1 for log in self.detection_logs if log['type'] == 'owner')
        intruder_detections = sum(1 for log in self.detection_logs if log['type'] == 'intruder')
        print(f"Authorized detections: {owner_detections}")
        print(f"Intruder detections: {intruder_detections}")

def main():
    detector = SmartIntruderDetector()
    try:
        detector.run()
    except KeyboardInterrupt:
        print("\n\n🛑 System stopped by user")
    except Exception as e:
        print(f"\n❌ System error: {e}")

if __name__ == "__main__":
    main()