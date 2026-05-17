"""
Full Simulation Script — Demo Without Hardware

Simulates the entire Eco-Acoustic Mesh pipeline with MULTIPLE NODES:
  - 5 sentinel nodes across the Masai Mara with unique profiles
  - Each node has distinct GPS, threat behavior, and battery characteristics
  - Generates synthetic audio (sine waves for threats, noise for ambient)
  - Runs through the preprocessing pipeline
  - Sends classification results to the gateway server
  - No microphone, LoRa hardware, or Ollama required

Usage:
    python scripts/simulate.py
    python scripts/simulate.py --gateway http://localhost:8000
    python scripts/simulate.py --gateway http://localhost:8000 --cycles 30
"""

import sys
import os
import time
import json
import random
import logging
import argparse
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.audio.buffer import CircularAudioBuffer
from sentinel.audio.preprocessor import AudioPreprocessor
from sentinel.comms.payload import (
    encode_alert, encode_heartbeat, decode_payload,
    ThreatCode, PayloadFlags, to_hex_string,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")
logger = logging.getLogger("simulator")

SAMPLE_RATE = 16000
DURATION = 5.0  # seconds


# =============================================
#  NODE PROFILES — 5 Sentinel Nodes in Masai Mara
# =============================================
NODE_PROFILES = {
    1: {
        "name": "Alpha - Forest Edge",
        "lat": -1.4725, "lon": 35.2558,
        "lat_jitter": 0.003, "lon_jitter": 0.003,
        "threat_weights": {
            "CHAINSAW": 0.28, "AXE": 0.14, "VEHICLE": 0.08, "GUNSHOT": 0.04,
            "TRAP_SNAP": 0.05, "DRONE": 0.03, "DOG_BARK": 0.02, "EXPLOSION": 0.01,
            "POACHER": 0.05, "AMBIENT": 0.30,
        },
        "battery_range": (55, 85), "temp_range": (42, 58),
        "description": "Near forest boundary \u2014 high logging risk",
    },
    2: {
        "name": "Bravo - Central Savanna",
        "lat": -1.5023, "lon": 35.1447,
        "lat_jitter": 0.005, "lon_jitter": 0.005,
        "threat_weights": {
            "VEHICLE": 0.26, "DRONE": 0.10, "DOG_BARK": 0.08, "GUNSHOT": 0.06,
            "CHAINSAW": 0.03, "AXE": 0.02, "TRAP_SNAP": 0.03, "EXPLOSION": 0.02,
            "POACHER": 0.05, "AMBIENT": 0.35,
        },
        "battery_range": (70, 98), "temp_range": (38, 50),
        "description": "Open plain \u2014 patrol vehicle detection",
    },
    3: {
        "name": "Charlie - River Crossing",
        "lat": -1.5341, "lon": 35.2012,
        "lat_jitter": 0.002, "lon_jitter": 0.002,
        "threat_weights": {
            "TRAP_SNAP": 0.18, "GUNSHOT": 0.14, "CHAINSAW": 0.10, "VEHICLE": 0.08,
            "DOG_BARK": 0.06, "AXE": 0.05, "DRONE": 0.03, "EXPLOSION": 0.02,
            "POACHER": 0.10, "AMBIENT": 0.24,
        },
        "battery_range": (45, 75), "temp_range": (44, 60),
        "description": "River crossing \u2014 poacher trap hotspot",
    },
    4: {
        "name": "Delta - East Boundary",
        "lat": -1.4891, "lon": 35.3105,
        "lat_jitter": 0.004, "lon_jitter": 0.004,
        "threat_weights": {
            "DRONE": 0.04, "VEHICLE": 0.03, "DOG_BARK": 0.03, "CHAINSAW": 0.02,
            "GUNSHOT": 0.01, "TRAP_SNAP": 0.01, "AXE": 0.01, "EXPLOSION": 0.01,
            "POACHER": 0.04, "AMBIENT": 0.80,
        },
        "battery_range": (80, 100), "temp_range": (35, 45),
        "description": "Quiet zone \u2014 monitoring baseline",
    },
    5: {
        "name": "Echo - West Hilltop",
        "lat": -1.5150, "lon": 35.0889,
        "lat_jitter": 0.003, "lon_jitter": 0.003,
        "threat_weights": {
            "GUNSHOT": 0.20, "EXPLOSION": 0.12, "DOG_BARK": 0.08, "VEHICLE": 0.06,
            "CHAINSAW": 0.05, "DRONE": 0.05, "AXE": 0.03, "TRAP_SNAP": 0.04,
            "POACHER": 0.05, "AMBIENT": 0.32,
        },
        "battery_range": (50, 80), "temp_range": (40, 52),
        "description": "Hilltop overwatch \u2014 gunshot & explosion detection",
    },
}

# Weather / environment simulation per region
WEATHER_PROFILES = [
    {"condition": "clear", "temp_c": 28, "humidity": 45, "wind_kph": 8, "rain_mm": 0},
    {"condition": "partly_cloudy", "temp_c": 25, "humidity": 55, "wind_kph": 12, "rain_mm": 0},
    {"condition": "overcast", "temp_c": 22, "humidity": 70, "wind_kph": 18, "rain_mm": 0},
    {"condition": "light_rain", "temp_c": 20, "humidity": 85, "wind_kph": 15, "rain_mm": 2},
    {"condition": "clear", "temp_c": 32, "humidity": 35, "wind_kph": 5, "rain_mm": 0},
]


def generate_chainsaw_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic chainsaw-like audio (buzzing + harmonics)."""
    t = np.linspace(0, duration, int(sr * duration), dtype=np.float32)
    # Base frequency with harmonics
    signal = (
        0.3 * np.sin(2 * np.pi * 200 * t)
        + 0.2 * np.sin(2 * np.pi * 400 * t)
        + 0.15 * np.sin(2 * np.pi * 800 * t)
        + 0.1 * np.sin(2 * np.pi * 1600 * t)
    )
    # Add amplitude modulation (load variation)
    modulation = 0.5 + 0.5 * np.sin(2 * np.pi * 3 * t)
    signal *= modulation
    # Add noise
    signal += 0.05 * np.random.randn(len(t)).astype(np.float32)
    return signal


def generate_gunshot_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic gunshot-like audio (impulse + decay)."""
    n = int(sr * duration)
    signal = np.zeros(n, dtype=np.float32)
    # Place 1-3 gunshot impulses
    num_shots = random.randint(1, 3)
    for i in range(num_shots):
        pos = int(n * (0.1 + 0.25 * i))
        if pos < n:
            # Sharp impulse
            impulse_len = int(sr * 0.02)
            end = min(pos + impulse_len, n)
            t_imp = np.arange(end - pos, dtype=np.float32)
            signal[pos:end] = 0.9 * np.exp(-t_imp / (sr * 0.003)) * np.sin(
                2 * np.pi * 2000 * t_imp / sr
            )
    # Add light ambient noise
    signal += 0.02 * np.random.randn(n).astype(np.float32)
    return signal


def generate_vehicle_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic engine/vehicle audio (low-freq rumble)."""
    t = np.linspace(0, duration, int(sr * duration), dtype=np.float32)
    signal = (
        0.3 * np.sin(2 * np.pi * 80 * t)
        + 0.2 * np.sin(2 * np.pi * 160 * t)
        + 0.1 * np.sin(2 * np.pi * 240 * t)
    )
    signal += 0.08 * np.random.randn(len(t)).astype(np.float32)
    return signal


def generate_ambient_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate quiet ambient noise (wind/nature)."""
    n = int(sr * duration)
    signal = 0.005 * np.random.randn(n).astype(np.float32)
    return signal


def generate_explosion_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic explosion (broadband blast + low-freq rumble + slow decay)."""
    n = int(sr * duration)
    signal = np.zeros(n, dtype=np.float32)
    # Main blast at start
    blast_len = int(sr * 0.15)
    blast = 0.95 * np.random.randn(blast_len).astype(np.float32)
    t_decay = np.linspace(1, 0, blast_len, dtype=np.float32) ** 0.5
    signal[:blast_len] = blast * t_decay
    # Low-frequency rumble tail
    t = np.linspace(0, duration, n, dtype=np.float32)
    rumble = 0.3 * np.sin(2 * np.pi * 35 * t) * np.exp(-t * 1.5)
    signal += rumble.astype(np.float32)
    signal += 0.02 * np.random.randn(n).astype(np.float32)
    return signal


def generate_trap_snap_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic metal trap snap (sharp metallic transient + ringing)."""
    n = int(sr * duration)
    signal = np.zeros(n, dtype=np.float32)
    # Sharp metallic click
    snap_pos = int(n * 0.15)
    snap_len = int(sr * 0.008)
    end = min(snap_pos + snap_len, n)
    t_snap = np.arange(end - snap_pos, dtype=np.float32)
    signal[snap_pos:end] = 0.85 * np.sin(2 * np.pi * 4500 * t_snap / sr) * np.exp(-t_snap / (sr * 0.002))
    # Metallic ringing decay
    ring_len = int(sr * 0.4)
    ring_end = min(snap_pos + ring_len, n)
    t_ring = np.arange(ring_end - snap_pos, dtype=np.float32)
    signal[snap_pos:ring_end] += 0.2 * np.sin(2 * np.pi * 2200 * t_ring / sr) * np.exp(-t_ring / (sr * 0.08))
    signal += 0.01 * np.random.randn(n).astype(np.float32)
    return signal


def generate_drone_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic drone buzz (multi-rotor high-pitched whine)."""
    t = np.linspace(0, duration, int(sr * duration), dtype=np.float32)
    # Multi-rotor propeller frequencies (4 rotors at slightly different speeds)
    signal = (
        0.2 * np.sin(2 * np.pi * 340 * t)
        + 0.18 * np.sin(2 * np.pi * 355 * t)
        + 0.15 * np.sin(2 * np.pi * 680 * t)
        + 0.12 * np.sin(2 * np.pi * 710 * t)
        + 0.08 * np.sin(2 * np.pi * 1020 * t)
    )
    # Slight pitch wobble (Doppler effect)
    wobble = 1.0 + 0.02 * np.sin(2 * np.pi * 0.8 * t)
    signal *= wobble
    signal += 0.04 * np.random.randn(len(t)).astype(np.float32)
    return signal


def generate_dog_bark_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic dog barking (pulsed mid-frequency bursts)."""
    n = int(sr * duration)
    signal = np.zeros(n, dtype=np.float32)
    # 3-6 bark bursts
    num_barks = random.randint(3, 6)
    for b in range(num_barks):
        bark_start = int(n * (0.08 + 0.16 * b))
        bark_len = int(sr * random.uniform(0.08, 0.15))
        if bark_start + bark_len > n:
            break
        t_bark = np.arange(bark_len, dtype=np.float32)
        freq = random.uniform(400, 700)
        bark = 0.6 * np.sin(2 * np.pi * freq * t_bark / sr)
        bark *= np.exp(-t_bark / (sr * 0.04))  # fast decay
        bark *= (0.5 + 0.5 * np.sin(2 * np.pi * 25 * t_bark / sr))  # modulation
        signal[bark_start:bark_start + bark_len] = bark
    signal += 0.015 * np.random.randn(n).astype(np.float32)
    return signal


def generate_axe_audio(duration=DURATION, sr=SAMPLE_RATE):
    """Generate synthetic axe chopping (rhythmic sharp impacts + wood crack)."""
    n = int(sr * duration)
    signal = np.zeros(n, dtype=np.float32)
    # 3-5 chop impacts
    num_chops = random.randint(3, 5)
    for c in range(num_chops):
        chop_pos = int(n * (0.1 + 0.2 * c))
        if chop_pos >= n:
            break
        # Impact transient (wood crack)
        imp_len = int(sr * 0.025)
        end = min(chop_pos + imp_len, n)
        t_imp = np.arange(end - chop_pos, dtype=np.float32)
        impact = 0.7 * np.exp(-t_imp / (sr * 0.005))
        impact *= np.sin(2 * np.pi * 1200 * t_imp / sr + random.uniform(0, 3.14))
        signal[chop_pos:end] = impact
        # Low wood thud
        thud_len = int(sr * 0.08)
        thud_end = min(chop_pos + thud_len, n)
        t_thud = np.arange(thud_end - chop_pos, dtype=np.float32)
        signal[chop_pos:thud_end] += 0.25 * np.sin(2 * np.pi * 120 * t_thud / sr) * np.exp(-t_thud / (sr * 0.02))
    signal += 0.02 * np.random.randn(n).astype(np.float32)
    return signal


def generate_poacher_cam_event(duration=DURATION, sr=SAMPLE_RATE):
    """Generate dummy audio for a camera detection event. 
       The camera doesn't use audio, but the simulation pipeline requires an audio buffer.
       We'll generate light ambient noise.
    """
    n = int(sr * duration)
    signal = 0.005 * np.random.randn(n).astype(np.float32)
    return signal


GENERATORS = {
    "CHAINSAW": (generate_chainsaw_audio, ThreatCode.CHAINSAW),
    "GUNSHOT": (generate_gunshot_audio, ThreatCode.GUNSHOT),
    "VEHICLE": (generate_vehicle_audio, ThreatCode.VEHICLE),
    "AMBIENT": (generate_ambient_audio, ThreatCode.AMBIENT),
    "EXPLOSION": (generate_explosion_audio, ThreatCode.EXPLOSION),
    "TRAP_SNAP": (generate_trap_snap_audio, ThreatCode.TRAP_SNAP),
    "DRONE": (generate_drone_audio, ThreatCode.DRONE),
    "DOG_BARK": (generate_dog_bark_audio, ThreatCode.DOG_BARK),
    "AXE": (generate_axe_audio, ThreatCode.AXE),
    "POACHER": (generate_poacher_cam_event, ThreatCode.POACHER),
}


def pick_scenario(node_profile):
    """Pick a threat scenario based on node's threat weight distribution."""
    weights = node_profile["threat_weights"]
    scenarios = list(weights.keys())
    probs = list(weights.values())
    return random.choices(scenarios, weights=probs, k=1)[0]


def get_jittered_location(node_profile):
    """Get GPS coordinates with small random jitter (simulates movement/drift)."""
    lat = node_profile["lat"] + random.uniform(
        -node_profile["lat_jitter"], node_profile["lat_jitter"]
    )
    lon = node_profile["lon"] + random.uniform(
        -node_profile["lon_jitter"], node_profile["lon_jitter"]
    )
    return lat, lon


def get_weather():
    """Pick a random weather condition."""
    return random.choice(WEATHER_PROFILES).copy()


def run_simulation(gateway_url=None, cycles=20):
    """Run a full multi-node simulation."""
    buffer = CircularAudioBuffer(duration_sec=DURATION, sample_rate=SAMPLE_RATE)
    preprocessor = AudioPreprocessor(
        sample_rate=SAMPLE_RATE, silence_threshold_db=-40.0
    )

    logger.info("=" * 60)
    logger.info("  ECO-ACOUSTIC MESH — MULTI-NODE SIMULATION")
    logger.info("=" * 60)
    logger.info(f"  Nodes: {len(NODE_PROFILES)}")
    for nid, prof in NODE_PROFILES.items():
        logger.info(f"    Node {nid}: {prof['name']} ({prof['description']})")
    logger.info(f"  Cycles: {cycles}")
    logger.info("=" * 60)

    # Track per-node battery (drains over time)
    node_batteries = {
        nid: random.randint(*prof["battery_range"])
        for nid, prof in NODE_PROFILES.items()
    }

    # Current weather (changes occasionally)
    current_weather = get_weather()
    weather_change_counter = 0

    node_ids = list(NODE_PROFILES.keys())

    for i in range(1, cycles + 1):
        # Rotate through nodes (each cycle picks a random node)
        node_id = random.choice(node_ids)
        profile = NODE_PROFILES[node_id]

        # Pick scenario based on this node's threat profile
        scenario = pick_scenario(profile)
        gen_func, threat_code = GENERATORS[scenario]
        audio = gen_func()

        # Write to buffer
        buffer.clear()
        buffer.write(audio)

        # Preprocess
        window = buffer.get_window()
        analysis, wav_bytes = preprocessor.process(window)

        is_threat = scenario != "AMBIENT"
        confidence = random.uniform(0.72, 0.98) if is_threat else random.uniform(0.08, 0.35)

        # Battery drain simulation
        drain = random.uniform(0.2, 0.8) if is_threat else random.uniform(0.05, 0.15)
        node_batteries[node_id] = max(5, node_batteries[node_id] - drain)

        # Occasional solar recharge
        if random.random() < 0.3:
            node_batteries[node_id] = min(100, node_batteries[node_id] + random.uniform(0.5, 2.0))

        # Weather change every ~8 cycles
        weather_change_counter += 1
        if weather_change_counter >= random.randint(6, 10):
            current_weather = get_weather()
            weather_change_counter = 0

        lat, lon = get_jittered_location(profile)
        battery_pct = int(node_batteries[node_id])
        cpu_temp = random.randint(*profile["temp_range"])

        logger.info(
            f"[{i}/{cycles}] Node {node_id} ({profile['name'][:12]:12s}) | "
            f"{scenario:10s} | "
            f"RMS: {analysis.rms_db:6.1f}dB | "
            f"Conf: {confidence:.2f} | "
            f"Bat: {battery_pct}%"
        )

        if is_threat and wav_bytes is not None:
            payload = encode_alert(
                threat_class=threat_code,
                confidence_pct=int(confidence * 100),
                lat_udeg=int(lat * 1e6),
                lon_udeg=int(lon * 1e6),
                node_id=node_id,
                audio_db=int(max(0, analysis.peak_db + 100)),
                temp_c=cpu_temp,
                battery_pct=battery_pct,
                flags=PayloadFlags.encode(gps_valid=True),
            )
            decoded = decode_payload(payload)
            logger.info(
                f"  -> LoRa Payload: {to_hex_string(payload)} "
                f"({len(payload)} bytes)"
            )
            logger.info(
                f"  -> ALERT: {decoded.threat_name} @ "
                f"({decoded.latitude:.4f}, {decoded.longitude:.4f})"
            )

            # POST threat to gateway
            if gateway_url:
                _post_to_gateway(
                    gateway_url, payload, confidence, scenario,
                    node_id, profile, lat, lon,
                    battery_pct, cpu_temp, analysis, current_weather
                )
        else:
            # POST heartbeat / ambient status to gateway
            if gateway_url:
                _post_heartbeat(
                    gateway_url, node_id, profile,
                    lat, lon, battery_pct, cpu_temp, current_weather
                )

        # Variable delay — threats report faster than ambient
        delay = random.uniform(0.3, 0.6) if is_threat else random.uniform(0.5, 1.0)
        time.sleep(delay)

    logger.info("=" * 60)
    logger.info("  SIMULATION COMPLETE")
    logger.info("  Final battery levels:")
    for nid, bat in node_batteries.items():
        logger.info(f"    Node {nid}: {int(bat)}%")
    logger.info("=" * 60)


def _post_to_gateway(url, payload_bytes, confidence, threat_class,
                     node_id, profile, lat, lon,
                     battery_pct, cpu_temp, analysis, weather):
    """POST a simulated threat alert to the gateway server."""
    try:
        import httpx

        # Compute severity
        conf_pct = int(confidence * 100)
        if threat_class in ("GUNSHOT", "POACHER") and conf_pct >= 80:
            severity = "critical"
        elif conf_pct >= 80:
            severity = "critical"
        elif conf_pct >= 60:
            severity = "warning"
        else:
            severity = "info"

        alert = {
            "msg_type": "alert",
            "threat": {
                "class": threat_class,
                "code": 0,
                "confidence": conf_pct,
                "severity": severity,
            },
            "location": {
                "latitude": round(lat, 6),
                "longitude": round(lon, 6),
                "gps_valid": True,
            },
            "timestamp": int(time.time()),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "node": {
                "id": node_id,
                "name": profile["name"],
                "battery_pct": battery_pct,
                "cpu_temp_c": cpu_temp,
                "audio_db": int(max(0, analysis.peak_db + 100)),
                "description": profile["description"],
            },
            "environment": {
                "weather": weather["condition"],
                "ambient_temp_c": weather["temp_c"] + random.randint(-2, 2),
                "humidity_pct": weather["humidity"] + random.randint(-5, 5),
                "wind_kph": weather["wind_kph"] + random.randint(-3, 3),
                "rain_mm": weather["rain_mm"],
                "solar_charging": battery_pct > 50 and weather["condition"] in ("clear", "partly_cloudy"),
                "signal_strength_dbm": random.randint(-90, -45),
                "packet_loss_pct": round(random.uniform(0, 8), 1),
            },
            "flags": {
                "gps_valid": True,
                "solar_charging": weather["condition"] in ("clear", "partly_cloudy"),
                "buffer_overflow": False,
            },
        }
        resp = httpx.post(f"{url}/api/simulate", json=alert, timeout=5)
        logger.info(f"  -> Gateway: {resp.status_code}")
    except Exception as e:
        logger.warning(f"  -> Gateway POST failed: {e}")


def _post_heartbeat(url, node_id, profile, lat, lon,
                    battery_pct, cpu_temp, weather):
    """POST a heartbeat (ambient/quiet) status to the gateway."""
    try:
        import httpx
        heartbeat = {
            "msg_type": "heartbeat",
            "threat": {
                "class": "AMBIENT",
                "code": 0,
                "confidence": 0,
                "severity": "info",
            },
            "location": {
                "latitude": round(lat, 6),
                "longitude": round(lon, 6),
                "gps_valid": True,
            },
            "timestamp": int(time.time()),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "node": {
                "id": node_id,
                "name": profile["name"],
                "battery_pct": battery_pct,
                "cpu_temp_c": cpu_temp,
                "audio_db": random.randint(5, 20),
                "description": profile["description"],
            },
            "environment": {
                "weather": weather["condition"],
                "ambient_temp_c": weather["temp_c"] + random.randint(-2, 2),
                "humidity_pct": weather["humidity"] + random.randint(-5, 5),
                "wind_kph": weather["wind_kph"] + random.randint(-3, 3),
                "rain_mm": weather["rain_mm"],
                "solar_charging": battery_pct > 50 and weather["condition"] in ("clear", "partly_cloudy"),
                "signal_strength_dbm": random.randint(-85, -40),
                "packet_loss_pct": round(random.uniform(0, 5), 1),
            },
            "flags": {
                "gps_valid": True,
                "solar_charging": weather["condition"] in ("clear", "partly_cloudy"),
                "buffer_overflow": False,
            },
        }
        resp = httpx.post(f"{url}/api/simulate", json=heartbeat, timeout=5)
    except Exception:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Eco-Mesh Multi-Node Simulator")
    parser.add_argument(
        "--gateway", type=str, default=None,
        help="Gateway server URL (e.g. http://localhost:8000)",
    )
    parser.add_argument(
        "--cycles", type=int, default=30,
        help="Number of simulation cycles (default: 30)",
    )
    args = parser.parse_args()
    run_simulation(gateway_url=args.gateway, cycles=args.cycles)
