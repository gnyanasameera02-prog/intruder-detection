from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, flash
from flask_socketio import SocketIO, emit
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
import base64
from PIL import Image
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

class WebIntruderDetector:
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
        self.camera = None
        self.detection_thread = None
        self.is_running = False

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

    def load_owner_images(self):
        """Load owner images from the owner_images directory"""
        owner_dir = Path("owner_images")
        images = list(owner_dir.glob("*.jpg")) + list(owner_dir.glob("*.png"))
        self.owner_images = [str(img) for img in images]
        return len(self.owner_images)

    def setup_email_config(self, smtp_server, smtp_port, sender_email, sender_password, owner_email):
        """Setup email configuration"""
        self.smtp_config = {
            'server': smtp_server,
            'port': smtp_port,
            'email': sender_email,
            'password': sender_password
        }
        self.owner_email = owner_email
        
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.quit()
            self.email_enabled = True
            return True
        except Exception as e:
            self.logger.error(f"Email configuration failed: {e}")
            return False

    def verify_face(self, frame):
        """Verify if the detected face belongs to an authorized owner"""
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

    def send_alert_email(self, frame, detection_type="intruder"):
        """Send alert email with captured frame"""
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
        """Log detection events"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': detection_type,
            'confidence': confidence,
            'status': 'alert_sent' if detection_type == 'intruder' else 'authorized'
        }
        self.detection_logs.append(log_entry)
        
        # Keep only last 100 logs
        if len(self.detection_logs) > 100:
            self.detection_logs = self.detection_logs[-100:]
            
        with open('logs/detection_logs.json', 'w') as f:
            json.dump(self.detection_logs, f, indent=2)

    def detection_loop(self):
        """Main detection loop that runs in a separate thread"""
        # Try different camera indices
        cap = None
        camera_indices = [0, 1, 2, -1]  # Try different camera indices
        
        for camera_index in camera_indices:
            try:
                cap = cv2.VideoCapture(camera_index)
                if cap.isOpened():
                    print(f"Camera opened successfully with index {camera_index}")
                    break
                else:
                    cap.release()
            except Exception as e:
                print(f"Failed to open camera with index {camera_index}: {e}")
                if cap:
                    cap.release()
        
        if not cap or not cap.isOpened():
            error_msg = "Could not open camera. Please check if camera is connected and not in use by another application."
            print(error_msg)
            socketio.emit('error', {'message': error_msg})
            return

        # Set camera properties
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        cap.set(cv2.CAP_PROP_FPS, 30)
        
        # Try to get a test frame to verify camera is working
        ret, test_frame = cap.read()
        if not ret or test_frame is None:
            error_msg = "Camera opened but cannot read frames. Please check camera permissions."
            print(error_msg)
            socketio.emit('error', {'message': error_msg})
            cap.release()
            return

        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        fps_counter = 0
        fps_start_time = time.time()
        frame_count = 0

        print("Camera detection loop started successfully")
        socketio.emit('camera_status', {'status': 'active'})

        while self.is_running:
            ret, frame = cap.read()
            if not ret or frame is None:
                print("Failed to read frame from camera")
                socketio.emit('error', {'message': 'Failed to read frame from camera'})
                break

            frame_count += 1
            frame = cv2.flip(frame, 1)  # Mirror the frame
            original_frame = frame.copy()
            
            fps_counter += 1
            if time.time() - fps_start_time >= 1.0:
                fps = fps_counter / (time.time() - fps_start_time)
                fps_counter = 0
                fps_start_time = time.time()
            else:
                fps = 0

            detection_status = "NO FACE DETECTED"
            face_detected = False

            if self.detection_active:
                try:
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    faces = face_cascade.detectMultiScale(gray, 1.3, 5)
                    
                    for (x, y, w, h) in faces:
                        face_detected = True
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
                                    threading.Thread(target=self.send_alert_email, args=(original_frame, "intruder")).start()
                                    self.last_alert_time = current_time
                                    self.log_detection("intruder", distance)
                                    socketio.emit('intruder_alert', {
                                        'timestamp': datetime.now().isoformat(),
                                        'confidence': distance
                                    })
                except Exception as e:
                    print(f"Error in face detection: {e}")
                    detection_status = "DETECTION ERROR"

            # Add status text to frame
            cv2.putText(frame, f"Status: {detection_status}", (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
            cv2.putText(frame, f"Detection: {'ON' if self.detection_active else 'OFF'}", (10, 60),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7,
                        (0, 255, 0) if self.detection_active else (0, 0, 255), 2)
            cv2.putText(frame, f"FPS: {fps:.1f}", (10, 90),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 0), 2)
            cv2.putText(frame, f"Frame: {frame_count}", (10, 120),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)

            try:
                # Convert frame to base64 for web display
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
                frame_base64 = base64.b64encode(buffer).decode('utf-8')
                
                # Emit frame data to connected clients
                socketio.emit('video_frame', {
                    'frame': frame_base64,
                    'status': detection_status,
                    'detection_active': self.detection_active,
                    'fps': fps,
                    'face_detected': face_detected,
                    'frame_count': frame_count
                })
            except Exception as e:
                print(f"Error encoding frame: {e}")

            time.sleep(0.033)  # ~30 FPS

        print("Camera detection loop stopped")
        socketio.emit('camera_status', {'status': 'inactive'})
        cap.release()

    def start_detection(self):
        """Start the detection system"""
        if not self.is_running:
            self.is_running = True
            self.detection_thread = threading.Thread(target=self.detection_loop)
            self.detection_thread.daemon = True
            self.detection_thread.start()
            return True
        return False

    def stop_detection(self):
        """Stop the detection system"""
        self.is_running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=1)
        return True

    def toggle_detection(self):
        """Toggle detection on/off"""
        self.detection_active = not self.detection_active
        return self.detection_active

    def update_threshold(self, new_threshold):
        """Update confidence threshold"""
        try:
            self.confidence_threshold = float(new_threshold)
            return True
        except ValueError:
            return False

    def get_detection_logs(self):
        """Get recent detection logs"""
        return self.detection_logs[-20:]  # Return last 20 logs

    def get_system_status(self):
        """Get current system status"""
        return {
            'detection_active': self.detection_active,
            'is_running': self.is_running,
            'email_enabled': self.email_enabled,
            'owner_images_count': len(self.owner_images),
            'confidence_threshold': self.confidence_threshold,
            'total_logs': len(self.detection_logs)
        }

# Global detector instance
detector = WebIntruderDetector()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/setup')
def setup():
    """Setup page"""
    return render_template('setup.html')

@app.route('/logs')
def logs():
    """Logs page"""
    return render_template('logs.html')

@app.route('/api/system/status')
def get_system_status():
    """API endpoint to get system status"""
    return jsonify(detector.get_system_status())

@app.route('/api/system/start', methods=['POST'])
def start_system():
    """API endpoint to start the detection system"""
    success = detector.start_detection()
    return jsonify({'success': success})

@app.route('/api/system/stop', methods=['POST'])
def stop_system():
    """API endpoint to stop the detection system"""
    success = detector.stop_detection()
    return jsonify({'success': success})

@app.route('/api/detection/toggle', methods=['POST'])
def toggle_detection():
    """API endpoint to toggle detection"""
    is_active = detector.toggle_detection()
    return jsonify({'detection_active': is_active})

@app.route('/api/threshold/update', methods=['POST'])
def update_threshold():
    """API endpoint to update confidence threshold"""
    data = request.get_json()
    new_threshold = data.get('threshold', 0.45)
    success = detector.update_threshold(new_threshold)
    return jsonify({'success': success})

@app.route('/api/logs')
def get_logs():
    """API endpoint to get detection logs"""
    logs = detector.get_detection_logs()
    return jsonify(logs)

@app.route('/api/setup/email', methods=['POST'])
def setup_email():
    """API endpoint to setup email configuration"""
    data = request.get_json()
    success = detector.setup_email_config(
        data.get('smtp_server'),
        int(data.get('smtp_port')),
        data.get('sender_email'),
        data.get('sender_password'),
        data.get('owner_email')
    )
    return jsonify({'success': success})

@app.route('/api/setup/owners', methods=['POST'])
def setup_owners():
    """API endpoint to load owner images"""
    count = detector.load_owner_images()
    return jsonify({'success': count > 0, 'count': count})

@app.route('/api/camera/test', methods=['GET'])
def test_camera():
    """API endpoint to test camera availability"""
    try:
        cap = cv2.VideoCapture(0)
        if cap.isOpened():
            ret, frame = cap.read()
            cap.release()
            if ret and frame is not None:
                return jsonify({'success': True, 'message': 'Camera is working properly'})
            else:
                return jsonify({'success': False, 'message': 'Camera opened but cannot read frames'})
        else:
            return jsonify({'success': False, 'message': 'Could not open camera'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Camera test failed: {str(e)}'})

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('system_status', detector.get_system_status())

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('camera_status')
def handle_camera_status(data):
    """Handle camera status updates"""
    print(f'Camera status: {data}')

if __name__ == '__main__':
    # Load existing owner images on startup
    detector.load_owner_images()
    
    # Start the Flask app with SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 