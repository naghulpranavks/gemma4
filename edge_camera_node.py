import time
import requests
import cv2  # OpenCV for camera/image handling
from ultralytics import YOLO

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
# The IP address of your Gateway server (if running locally, use localhost)
GATEWAY_URL = "http://localhost:8000/api/simulate"

# Your Sentinel Node ID (e.g., Node 6 for a new Camera Node)
NODE_ID = 6

# Load the model you downloaded from Roboflow
# Note: You must put the actual path to your downloaded best.pt file here!
try:
    model = YOLO("yolov8n.pt") 
    print("Model loaded successfully!")
except Exception as e:
    print(f"Warning: Could not load model. Error: {e}")
    model = None

# ---------------------------------------------------------
# Threat Mapping (matches payload.py ThreatCode)
# ---------------------------------------------------------
# Roboflow might output class names like 'poacher' or 'vehicle'
# We map these to our binary protocol codes
CLASS_MAP = {
    "person": 0x0A,  # Map YOLO's 'person' to our POACHER alert
    "car": 0x03,     # Map 'car' to VEHICLE alert
    "truck": 0x03    # Map 'truck' to VEHICLE alert
}

def build_lora_payload(threat_code, confidence_pct):
    """
    Builds the 20-byte EcoMesh binary payload.
    (Simplified version of what the C++ firmware does)
    """
    # 0x01 = Protocol Version
    # Node ID
    # Threat Code
    # Confidence (hex)
    # ... mock GPS for demo purposes ...
    
    # Format: Version(1) Node(1) Threat(1) Conf(1) Lat(4) Lon(4) Temp(2) Bat(1) Audio(1) Padding(4)
    # Here we just generate the exact JSON the gateway expects to simulate the LoRa bridge
    return {
        "hex_payload": "mock_camera_payload", # The gateway usually decodes this
        "msg_type": "alert",
        "node_id": NODE_ID,
        "threat_class": threat_code,
        "confidence": confidence_pct,
        "latitude": -1.5000,   # Mock camera GPS
        "longitude": 35.2000,
        "battery_pct": 95,
        "cpu_temp_c": 45,
        "audio_db": 0          # Cameras don't report audio DB
    }

def process_image(image_path):
    """Run inference on an image and send alerts if found."""
    if not model:
        print("Model not loaded. Cannot process image.")
        return

    print(f"Analyzing {image_path}...")
    
    # Run YOLOv8 inference
    results = model(image_path)
    
    found_threat = False

    for result in results:
        boxes = result.boxes
        for box in boxes:
            # Get confidence (0.0 to 1.0)
            conf = float(box.conf[0])
            conf_pct = int(conf * 100)
            
            # Get class name
            cls_id = int(box.cls[0])
            class_name = model.names[cls_id].lower()

            if conf_pct >= 60 and class_name in CLASS_MAP:
                found_threat = True
                threat_code = CLASS_MAP[class_name]
                print(f"⚠️ DETECTED: {class_name.upper()} (Confidence: {conf_pct}%)")
                
                # Send the alert to the gateway
                payload = build_lora_payload(threat_code, conf_pct)
                try:
                    response = requests.post(GATEWAY_URL, json=payload)
                    if response.status_code == 200:
                        print("✅ Alert transmitted to Gateway successfully!")
                except Exception as e:
                    print(f"❌ Failed to reach Gateway: {e}")

    if not found_threat:
        print("✅ Frame clear. No threats detected.")

# ---------------------------------------------------------
# Main Execution (Example Usage)
# ---------------------------------------------------------
if __name__ == "__main__":
    print("--- Sentinel Edge Camera Node Started ---")
    
    # We will test the node directly on the trail-camera image we generated earlier
    image_to_test = "dashboard/assets/images/poacher.png"
    
    # Let's wait a few seconds to let the server process finish starting if it just booted
    time.sleep(2)
    process_image(image_to_test)
