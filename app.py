from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
import os
import json
import random
import math
import re
from datetime import datetime
from io import BytesIO
from werkzeug.utils import secure_filename
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns


app = Flask(__name__)
app.secret_key = 'malware_detection_secret_key_2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Create necessary directories
os.makedirs('static/images', exist_ok=True)
os.makedirs('uploads', exist_ok=True)
os.makedirs('models', exist_ok=True)

# Global variables for model
model = None
scaler = None
label_encoders = None
target_encoder = None
feature_columns = None
is_multiclass = None
latest_report_cache = None

# Pre-defined sample values for different malware types
SAMPLE_VALUES = {
    'ransomware': {
        'name': 'Ransomware (WannaCry Style)',
        'icon': '🔴',
        'description': 'Encrypts files and demands ransom payment',
        'values': {
            'file_size_bytes': 245760,
            'entropy': 7.89,
            'pe_features': 42,
            'section_count': 8,
            'imports_count': 156,
            'exports_count': 12,
            'api_calls_count': 875,
            'suspicious_api_calls': 234,
            'network_connections': 45,
            'unique_ips': 23,
            'dns_requests': 38,
            'registry_changes': 156,
            'file_operations': 2345,
            'process_injections': 1,
            'code_obfuscation': 1,
            'packer_detected': 1,
            'anti_debug_techniques': 1,
            'vm_detection': 0,
            'encryption_usage': 1,
            'cpu_usage_percent': 45.6,
            'memory_usage_mb': 324.5,
            'persistence_mechanisms': 2,
            'command_control_channels': 3,
            'data_exfiltration': 1,
            'privilege_escalation': 1,
            'signature_valid': 0
        }
    },
    'trojan': {
        'name': 'Trojan (Banking Trojan)',
        'icon': '🟠',
        'description': 'Disguised as legitimate software, steals credentials',
        'values': {
            'file_size_bytes': 512000,
            'entropy': 7.12,
            'pe_features': 38,
            'section_count': 6,
            'imports_count': 234,
            'exports_count': 5,
            'api_calls_count': 654,
            'suspicious_api_calls': 178,
            'network_connections': 67,
            'unique_ips': 34,
            'dns_requests': 45,
            'registry_changes': 89,
            'file_operations': 234,
            'process_injections': 1,
            'code_obfuscation': 1,
            'packer_detected': 0,
            'anti_debug_techniques': 0,
            'vm_detection': 0,
            'encryption_usage': 0,
            'cpu_usage_percent': 23.4,
            'memory_usage_mb': 189.2,
            'persistence_mechanisms': 1,
            'command_control_channels': 2,
            'data_exfiltration': 1,
            'privilege_escalation': 0,
            'signature_valid': 0
        }
    },
    'worm': {
        'name': 'Worm (Conficker Style)',
        'icon': '🐛',
        'description': 'Self-replicating malware that spreads through networks',
        'values': {
            'file_size_bytes': 98304,
            'entropy': 6.78,
            'pe_features': 35,
            'section_count': 5,
            'imports_count': 123,
            'exports_count': 3,
            'api_calls_count': 432,
            'suspicious_api_calls': 89,
            'network_connections': 234,
            'unique_ips': 156,
            'dns_requests': 189,
            'registry_changes': 45,
            'file_operations': 567,
            'process_injections': 0,
            'code_obfuscation': 0,
            'packer_detected': 0,
            'anti_debug_techniques': 0,
            'vm_detection': 0,
            'encryption_usage': 0,
            'cpu_usage_percent': 34.5,
            'memory_usage_mb': 145.6,
            'persistence_mechanisms': 1,
            'command_control_channels': 4,
            'data_exfiltration': 0,
            'privilege_escalation': 0,
            'signature_valid': 0
        }
    },
    'spyware': {
        'name': 'Spyware (Keylogger)',
        'icon': '👁️',
        'description': 'Steals user data and monitors activities',
        'values': {
            'file_size_bytes': 196608,
            'entropy': 6.45,
            'pe_features': 28,
            'section_count': 4,
            'imports_count': 187,
            'exports_count': 2,
            'api_calls_count': 345,
            'suspicious_api_calls': 123,
            'network_connections': 34,
            'unique_ips': 12,
            'dns_requests': 28,
            'registry_changes': 67,
            'file_operations': 123,
            'process_injections': 0,
            'code_obfuscation': 1,
            'packer_detected': 0,
            'anti_debug_techniques': 0,
            'vm_detection': 0,
            'encryption_usage': 0,
            'cpu_usage_percent': 12.3,
            'memory_usage_mb': 78.4,
            'persistence_mechanisms': 1,
            'command_control_channels': 1,
            'data_exfiltration': 1,
            'privilege_escalation': 0,
            'signature_valid': 0
        }
    },
    'cryptominer': {
        'name': 'Cryptominer (CoinMiner)',
        'icon': '💰',
        'description': 'Uses system resources for cryptocurrency mining',
        'values': {
            'file_size_bytes': 131072,
            'entropy': 5.67,
            'pe_features': 25,
            'section_count': 3,
            'imports_count': 89,
            'exports_count': 1,
            'api_calls_count': 234,
            'suspicious_api_calls': 45,
            'network_connections': 12,
            'unique_ips': 3,
            'dns_requests': 8,
            'registry_changes': 34,
            'file_operations': 56,
            'process_injections': 0,
            'code_obfuscation': 0,
            'packer_detected': 0,
            'anti_debug_techniques': 0,
            'vm_detection': 0,
            'encryption_usage': 0,
            'cpu_usage_percent': 89.7,
            'memory_usage_mb': 234.5,
            'persistence_mechanisms': 1,
            'command_control_channels': 1,
            'data_exfiltration': 0,
            'privilege_escalation': 0,
            'signature_valid': 0
        }
    },
    'banking_trojan': {
        'name': 'Banking Trojan (Zeus)',
        'icon': '🏦',
        'description': 'Steals banking credentials and financial information',
        'values': {
            'file_size_bytes': 327680,
            'entropy': 7.34,
            'pe_features': 41,
            'section_count': 7,
            'imports_count': 267,
            'exports_count': 4,
            'api_calls_count': 543,
            'suspicious_api_calls': 198,
            'network_connections': 56,
            'unique_ips': 28,
            'dns_requests': 42,
            'registry_changes': 78,
            'file_operations': 145,
            'process_injections': 1,
            'code_obfuscation': 1,
            'packer_detected': 1,
            'anti_debug_techniques': 1,
            'vm_detection': 0,
            'encryption_usage': 0,
            'cpu_usage_percent': 18.9,
            'memory_usage_mb': 156.7,
            'persistence_mechanisms': 2,
            'command_control_channels': 3,
            'data_exfiltration': 1,
            'privilege_escalation': 0,
            'signature_valid': 0
        }
    },
    'rootkit': {
        'name': 'Rootkit (Stealth)',
        'icon': '🎭',
        'description': 'Hides malicious activities from detection',
        'values': {
            'file_size_bytes': 450560,
            'entropy': 7.45,
            'pe_features': 47,
            'section_count': 9,
            'imports_count': 198,
            'exports_count': 7,
            'api_calls_count': 456,
            'suspicious_api_calls': 145,
            'network_connections': 23,
            'unique_ips': 8,
            'dns_requests': 15,
            'registry_changes': 234,
            'file_operations': 678,
            'process_injections': 1,
            'code_obfuscation': 1,
            'packer_detected': 1,
            'anti_debug_techniques': 1,
            'vm_detection': 1,
            'encryption_usage': 0,
            'cpu_usage_percent': 8.2,
            'memory_usage_mb': 56.3,
            'persistence_mechanisms': 2,
            'command_control_channels': 1,
            'data_exfiltration': 0,
            'privilege_escalation': 1,
            'signature_valid': 0
        }
    },
    'adware': {
        'name': 'Adware (Popup Generator)',
        'icon': '📢',
        'description': 'Displays unwanted advertisements',
        'values': {
            'file_size_bytes': 88064,
            'entropy': 5.12,
            'pe_features': 19,
            'section_count': 3,
            'imports_count': 67,
            'exports_count': 0,
            'api_calls_count': 123,
            'suspicious_api_calls': 23,
            'network_connections': 45,
            'unique_ips': 18,
            'dns_requests': 34,
            'registry_changes': 56,
            'file_operations': 78,
            'process_injections': 0,
            'code_obfuscation': 0,
            'packer_detected': 0,
            'anti_debug_techniques': 0,
            'vm_detection': 0,
            'encryption_usage': 0,
            'cpu_usage_percent': 6.7,
            'memory_usage_mb': 67.8,
            'persistence_mechanisms': 1,
            'command_control_channels': 1,
            'data_exfiltration': 0,
            'privilege_escalation': 0,
            'signature_valid': 0
        }
    },
    'benign': {
        'name': 'Benign Software (Safe)',
        'icon': '✅',
        'description': 'Legitimate software - No malware detected',
        'values': {
            'file_size_bytes': 1048576,
            'entropy': 4.23,
            'pe_features': 18,
            'section_count': 4,
            'imports_count': 45,
            'exports_count': 0,
            'api_calls_count': 89,
            'suspicious_api_calls': 5,
            'network_connections': 2,
            'unique_ips': 1,
            'dns_requests': 2,
            'registry_changes': 12,
            'file_operations': 34,
            'process_injections': 0,
            'code_obfuscation': 0,
            'packer_detected': 0,
            'anti_debug_techniques': 0,
            'vm_detection': 0,
            'encryption_usage': 0,
            'cpu_usage_percent': 5.2,
            'memory_usage_mb': 45.6,
            'persistence_mechanisms': 0,
            'command_control_channels': 0,
            'data_exfiltration': 0,
            'privilege_escalation': 0,
            'signature_valid': 1
        }
    }
}

def load_model():
    """Load the trained model"""
    global model, scaler, label_encoders, target_encoder, feature_columns, is_multiclass
    
    try:
        if os.path.exists('models/malware_model.keras'):
            model = tf.keras.models.load_model('models/malware_model.keras')
            print("Model loaded successfully from malware_model.keras")
        elif os.path.exists('models/malware_model.h5'):
            model = tf.keras.models.load_model('models/malware_model.h5')
            print("Model loaded from legacy format malware_model.h5")
        else:
            print("No model found")
            return False
        
        scaler = joblib.load('models/scaler.pkl')
        label_encoders = joblib.load('models/label_encoders.pkl')
        target_encoder = joblib.load('models/target_encoder.pkl')
        feature_columns = joblib.load('models/feature_columns.pkl')
        is_multiclass = joblib.load('models/is_multiclass.pkl')
        
        print(f"Model loaded successfully!")
        print(f"Multi-class: {is_multiclass}")
        print(f"Classes: {target_encoder.classes_}")
        return True
    except Exception as e:
        print(f"Error loading model: {e}")
        return False


def extract_top_indicators(features, limit=5):
    """Return top numeric indicators from extracted feature values."""
    numeric_items = []
    for key, value in features.items():
        try:
            numeric_value = float(value)
            numeric_items.append((key, numeric_value))
        except (TypeError, ValueError):
            continue

    numeric_items.sort(key=lambda item: item[1], reverse=True)
    top = []
    for key, value in numeric_items[:limit]:
        top.append({
            'name': key,
            'label': key.replace('_', ' ').title(),
            'value': value
        })
    return top


def make_json_safe(data):
    """Recursively convert values into JSON-serializable primitives."""
    if isinstance(data, dict):
        return {str(k): make_json_safe(v) for k, v in data.items()}
    if isinstance(data, list):
        return [make_json_safe(v) for v in data]
    if isinstance(data, tuple):
        return [make_json_safe(v) for v in data]
    if isinstance(data, np.integer):
        return int(data)
    if isinstance(data, np.floating):
        return float(data)
    if isinstance(data, np.ndarray):
        return [make_json_safe(v) for v in data.tolist()]
    return data


def _escape_pdf_text(text):
    """Escape text content for a raw PDF text stream."""
    value = str(text)
    value = value.replace('\\', '\\\\')
    value = value.replace('(', '\\(')
    value = value.replace(')', '\\)')
    return value


def generate_basic_pdf_report(result):
    """Generate a styled PDF without external dependencies."""
    confidence_pct = float(result.get('probability_raw', 0) or 0) * 100
    risk_level = str(result.get('risk_level', 'Unknown'))
    risk_rgb = {
        'Critical': (0.75, 0.11, 0.14),
        'High': (0.92, 0.38, 0.08),
        'Medium': (0.86, 0.52, 0.08),
        'Low': (0.10, 0.55, 0.22),
        'No Action': (0.33, 0.36, 0.41)
    }.get(risk_level, (0.20, 0.25, 0.30))

    stream_lines = []

    # Header
    stream_lines.extend([
        '0.06 0.09 0.17 rg',
        '0 748 595 94 re f',
        '1 1 1 rg',
        'BT /F2 18 Tf 36 804 Td (MalwareGuard - Detection Intelligence Report) Tj ET',
        f"BT /F1 10 Tf 36 784 Td (Incident ID: {_escape_pdf_text(result.get('incident_id', 'N/A'))}) Tj ET",
        f"BT /F1 10 Tf 260 784 Td (Generated: {_escape_pdf_text(result.get('generated_at', 'N/A'))}) Tj ET"
    ])

    # Risk badge
    stream_lines.append(f"{risk_rgb[0]:.2f} {risk_rgb[1]:.2f} {risk_rgb[2]:.2f} rg")
    stream_lines.append('450 770 110 22 re f')
    stream_lines.append('1 1 1 rg')
    stream_lines.append(f"BT /F2 10 Tf 462 778 Td ({_escape_pdf_text(risk_level.upper() + ' RISK')}) Tj ET")

    # Watermark
    stream_lines.extend([
        'q',
        '0.90 0.93 0.97 rg',
        'BT /F2 44 Tf 105 420 Td (MALWAREGUARD) Tj ET',
        'Q'
    ])

    # Executive panel
    stream_lines.extend([
        '0.93 0.95 0.98 rg',
        '34 662 528 72 re f',
        '0.10 0.14 0.20 rg',
        'BT /F2 12 Tf 44 713 Td (Executive Summary) Tj ET',
        f"BT /F1 10 Tf 44 696 Td (Prediction: {_escape_pdf_text(result.get('malware_type', 'Unknown'))}) Tj ET",
        f"BT /F1 10 Tf 44 681 Td (Status: {_escape_pdf_text('Malware Detected' if result.get('is_malware') else 'No Malware Detected')}) Tj ET",
        f"BT /F1 10 Tf 300 696 Td (Confidence: {_escape_pdf_text(result.get('probability', 'N/A'))}) Tj ET",
        f"BT /F1 10 Tf 300 681 Td (Risk Level: {_escape_pdf_text(risk_level)}) Tj ET"
    ])

    # Confidence bar
    stream_lines.extend([
        '0.10 0.14 0.20 rg',
        'BT /F2 11 Tf 44 647 Td (Confidence Meter) Tj ET',
        '0.90 0.93 0.97 rg',
        '44 634 470 11 re f'
    ])
    fill_width = max(0.0, min(470.0, 4.70 * confidence_pct))
    stream_lines.append('0.94 0.27 0.23 rg' if result.get('is_malware') else '0.09 0.64 0.50 rg')
    stream_lines.append(f"44 634 {fill_width:.2f} 11 re f")
    stream_lines.extend([
        '0.10 0.14 0.20 rg',
        f"BT /F1 9 Tf 520 637 Td ({confidence_pct:.2f}%) Tj ET"
    ])

    # Probability section
    probs = result.get('all_probabilities') or {
        result.get('malware_type', 'Prediction'): float(result.get('probability_raw', 0) or 0)
    }
    sorted_probs = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)[:6]
    y = 610
    stream_lines.extend([
        '0.10 0.14 0.20 rg',
        'BT /F2 11 Tf 44 612 Td (Probability Distribution) Tj ET'
    ])
    for cls, prob in sorted_probs:
        p = float(prob) * 100
        y -= 18
        bar_width = 180.0 * float(prob)
        stream_lines.extend([
            '0.10 0.14 0.20 rg',
            f"BT /F1 9 Tf 44 {y+4:.0f} Td ({_escape_pdf_text(str(cls)[:25])}) Tj ET",
            f"BT /F1 9 Tf 220 {y+4:.0f} Td ({p:.2f}%) Tj ET",
            '0.90 0.93 0.97 rg',
            f"300 {y} 180 9 re f"
        ])
        stream_lines.append('0.94 0.27 0.23 rg' if cls == result.get('malware_type') else '0.23 0.51 0.96 rg')
        stream_lines.append(f"300 {y} {bar_width:.2f} 9 re f")

    # Indicators
    top_indicators = result.get('top_indicators', [])
    y = 470
    stream_lines.extend([
        '0.10 0.14 0.20 rg',
        'BT /F2 11 Tf 44 470 Td (Top Behavioral Indicators) Tj ET'
    ])
    if top_indicators:
        for idx, item in enumerate(top_indicators[:6], start=1):
            label = _escape_pdf_text(item.get('label', item.get('name', 'Indicator')))
            value = float(item.get('value', 0) or 0)
            y -= 15
            stream_lines.append(f"BT /F1 9 Tf 46 {y} Td ({idx}. {label}: {value:.2f}) Tj ET")
    else:
        stream_lines.append('BT /F1 9 Tf 46 455 Td (No indicators available) Tj ET')

    # Recommendations
    recommendations = result.get('recommendations', [])
    y = 360
    stream_lines.extend([
        '0.10 0.14 0.20 rg',
        'BT /F2 11 Tf 44 360 Td (Recommended Actions) Tj ET'
    ])
    for idx, recommendation in enumerate(recommendations[:8], start=1):
        y -= 14
        text = _escape_pdf_text(str(recommendation)[:115])
        stream_lines.append(f"BT /F1 9 Tf 46 {y} Td ({idx}. {text}) Tj ET")

    # Footer
    stream_lines.extend([
        '0.25 0.30 0.35 rg',
        'BT /F1 8 Tf 36 26 Td (Generated by MalwareGuard | Enhanced fallback PDF mode) Tj ET'
    ])

    stream_content = '\n'.join(stream_lines).encode('latin-1', errors='replace')

    objects = []
    objects.append(b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n')
    objects.append(b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n')
    objects.append(
        b'3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
        b'/Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> /Contents 4 0 R >>\nendobj\n'
    )
    objects.append(
        b'4 0 obj\n<< /Length ' + str(len(stream_content)).encode('ascii') +
        b' >>\nstream\n' + stream_content + b'\nendstream\nendobj\n'
    )
    objects.append(b'5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n')
    objects.append(b'6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n')

    pdf = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_pos = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode('ascii'))
    pdf.extend(b'0000000000 65535 f \n')
    for off in offsets[1:]:
        pdf.extend(f"{off:010d} 00000 n \n".encode('ascii'))

    trailer = (
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF"
    )
    pdf.extend(trailer.encode('ascii'))

    buffer = BytesIO(bytes(pdf))
    buffer.seek(0)
    return buffer


def generate_pdf_report(result):
    """Generate a high-end, visually rich PDF report from prediction results."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.colors import HexColor
        from reportlab.pdfgen import canvas
        from reportlab.lib.utils import ImageReader
    except Exception:
        return generate_basic_pdf_report(result)

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    confidence_pct = float(result.get('probability_raw', 0) or 0) * 100
    risk_level = str(result.get('risk_level', 'Unknown'))
    risk_color_map = {
        'Critical': '#b91c1c',
        'High': '#ea580c',
        'Medium': '#d97706',
        'Low': '#15803d',
        'No Action': '#475569'
    }
    risk_color = HexColor(risk_color_map.get(risk_level, '#334155'))

    probs = result.get('all_probabilities') or {
        result.get('malware_type', 'Prediction'): float(result.get('probability_raw', 0) or 0)
    }
    sorted_probs = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)

    project_title = 'ANN-Based Malware Detection Intelligence System'
    institute_name = 'Final Year Project Report'

    def wrap_text(text, max_chars=90):
        words = str(text).split()
        lines = []
        current = ''
        for word in words:
            proposal = f"{current} {word}".strip()
            if len(proposal) <= max_chars:
                current = proposal
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines or ['']

    def create_probability_chart():
        labels = [str(k) for k, _ in sorted_probs[:6]]
        values = [float(v) * 100 for _, v in sorted_probs[:6]]
        fig, ax = plt.subplots(figsize=(6.8, 2.8), dpi=150)
        colors = ['#ef4444' if label == result.get('malware_type') else '#3b82f6' for label in labels]
        ax.barh(labels[::-1], values[::-1], color=colors[::-1])
        ax.set_xlim(0, 100)
        ax.set_xlabel('Probability %')
        ax.set_title('Class Probability Distribution', pad=10)
        ax.grid(axis='x', alpha=0.2)
        ax.set_facecolor('#f8fafc')
        fig.patch.set_facecolor('#f8fafc')
        buf = BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format='png')
        plt.close(fig)
        buf.seek(0)
        return buf

    def create_indicator_chart():
        top = result.get('top_indicators', [])[:6]
        if not top:
            return None
        labels = [item.get('label', item.get('name', 'Indicator'))[:24] for item in top]
        values = [float(item.get('value', 0) or 0) for item in top]
        fig, ax = plt.subplots(figsize=(6.8, 2.6), dpi=150)
        ax.bar(labels, values, color='#14b8a6')
        ax.set_title('Top Behavioral Indicators', pad=10)
        ax.tick_params(axis='x', rotation=25)
        ax.grid(axis='y', alpha=0.2)
        ax.set_facecolor('#f8fafc')
        fig.patch.set_facecolor('#f8fafc')
        buf = BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format='png')
        plt.close(fig)
        buf.seek(0)
        return buf

    def draw_header_footer():
        c.setFillColor(HexColor('#0f172a'))
        c.rect(0, height - 96, width, 96, fill=1, stroke=0)
        c.setFillColor(HexColor('#e2e8f0'))
        c.setFont('Helvetica-Bold', 20)
        c.drawString(34, height - 50, 'MalwareGuard - Advanced Threat Intelligence Report')
        c.setFont('Helvetica', 9)
        c.drawString(34, height - 71, f"Generated: {result.get('generated_at', 'N/A')}")
        c.drawString(260, height - 71, f"Incident: {result.get('incident_id', 'N/A')}")

        c.saveState()
        c.setFillColor(HexColor('#dbeafe'))
        c.setFont('Helvetica-Bold', 44)
        c.translate(width / 2, height / 2)
        c.rotate(35)
        c.drawCentredString(0, 0, 'MALWAREGUARD')
        c.restoreState()

        c.setFillColor(HexColor('#475569'))
        c.setFont('Helvetica-Oblique', 8)
        c.drawString(34, 22, 'Security analysis report generated for educational demonstration')
        c.drawRightString(width - 34, 22, f"Page {c.getPageNumber()}")

    def draw_cover_page():
        c.setFillColor(HexColor('#0b1220'))
        c.rect(0, 0, width, height, fill=1, stroke=0)

        c.setFillColor(HexColor('#14b8a6'))
        c.circle(90, height - 90, 28, stroke=0, fill=1)
        c.setFillColor(HexColor('#0b1220'))
        c.setFont('Helvetica-Bold', 16)
        c.drawCentredString(90, height - 96, 'MG')

        c.setFillColor(HexColor('#e2e8f0'))
        c.setFont('Helvetica-Bold', 28)
        c.drawString(140, height - 84, 'MalwareGuard')

        c.setFillColor(HexColor('#38bdf8'))
        c.roundRect(36, height - 180, width - 72, 50, 10, fill=1, stroke=0)
        c.setFillColor(HexColor('#0b1220'))
        c.setFont('Helvetica-Bold', 15)
        c.drawCentredString(width / 2, height - 160, project_title)

        c.setFillColor(HexColor('#cbd5e1'))
        c.setFont('Helvetica', 12)
        c.drawCentredString(width / 2, height - 208, institute_name)

        c.setFillColor(HexColor('#94a3b8'))
        c.setFont('Helvetica', 11)
        c.drawCentredString(width / 2, height - 250, f"Incident ID: {result.get('incident_id', 'N/A')}")
        c.drawCentredString(width / 2, height - 270, f"Generated On: {result.get('generated_at', 'N/A')}")

        c.setFillColor(HexColor('#334155'))
        c.roundRect(60, 120, width - 120, 120, 12, fill=1, stroke=0)
        c.setFillColor(HexColor('#e2e8f0'))
        c.setFont('Helvetica-Bold', 13)
        c.drawString(80, 210, 'Submission Snapshot')
        c.setFont('Helvetica', 11)
        c.drawString(80, 188, f"Primary Prediction: {result.get('malware_type', 'Unknown')}")
        c.drawString(80, 170, f"Confidence: {result.get('probability', 'N/A')}")
        c.drawString(80, 152, f"Risk Level: {result.get('risk_level', 'N/A')}")

        c.setFillColor(HexColor('#64748b'))
        c.setFont('Helvetica-Oblique', 9)
        c.drawCentredString(width / 2, 50, 'Prepared for academic evaluation and project demonstration')
        c.showPage()

    def draw_toc_page():
        c.setFillColor(HexColor('#0f172a'))
        c.rect(0, height - 92, width, 92, fill=1, stroke=0)
        c.setFillColor(HexColor('#e2e8f0'))
        c.setFont('Helvetica-Bold', 22)
        c.drawString(36, height - 54, 'Table of Contents')

        c.setFillColor(HexColor('#0f172a'))
        c.setFont('Helvetica', 12)
        items = [
            ('1. Executive Summary', '03'),
            ('2. Risk and Confidence Analytics', '03'),
            ('3. Probability Distribution Chart', '03'),
            ('4. Behavioral Indicator Analysis', '04'),
            ('5. Analyst Insights', '04'),
            ('6. Recommended Action Plan', '04'),
            ('7. Declaration and Signature', '05')
        ]
        y_local = height - 140
        for title, page_no in items:
            c.drawString(52, y_local, title)
            c.drawRightString(width - 52, y_local, page_no)
            c.setStrokeColor(HexColor('#cbd5e1'))
            c.line(48, y_local - 6, width - 48, y_local - 6)
            y_local -= 32

        c.setFillColor(HexColor('#475569'))
        c.setFont('Helvetica-Oblique', 9)
        c.drawString(36, 28, 'Navigation map for the generated incident report')
        c.showPage()

    def ensure_space(current_y, required_height):
        if current_y - required_height < 58:
            c.showPage()
            draw_header_footer()
            return height - 122
        return current_y

    draw_cover_page()
    draw_toc_page()
    draw_header_footer()
    y = height - 126

    # Executive summary card
    c.setFillColor(HexColor('#f1f5f9'))
    c.roundRect(30, y - 85, width - 60, 92, 12, fill=1, stroke=0)
    c.setFillColor(HexColor('#0f172a'))
    c.setFont('Helvetica-Bold', 12)
    c.drawString(42, y - 15, 'Executive Summary')
    c.setFont('Helvetica', 10)
    c.drawString(42, y - 33, f"Predicted Threat: {result.get('malware_type', 'Unknown')}")
    c.drawString(42, y - 49, f"Detection Status: {'Malware Detected' if result.get('is_malware') else 'No Malware Detected'}")
    c.drawString(42, y - 65, f"Confidence: {result.get('probability', 'N/A')} ({confidence_pct:.2f}%)")
    c.drawString(300, y - 33, f"Risk Level: {risk_level}")

    # Risk badge and score
    c.setFillColor(risk_color)
    c.roundRect(width - 170, y - 72, 130, 30, 7, fill=1, stroke=0)
    c.setFillColor(HexColor('#ffffff'))
    c.setFont('Helvetica-Bold', 10)
    c.drawCentredString(width - 105, y - 54, f"{risk_level.upper()} RISK")
    c.setFont('Helvetica', 9)
    c.drawCentredString(width - 105, y - 66, f"Threat Score: {confidence_pct:.2f}")
    y -= 102

    # Confidence meter
    c.setFillColor(HexColor('#0f172a'))
    c.setFont('Helvetica-Bold', 12)
    c.drawString(40, y, 'Confidence Meter')
    y -= 16
    c.setFillColor(HexColor('#e2e8f0'))
    c.roundRect(40, y - 10, width - 80, 14, 7, fill=1, stroke=0)
    c.setFillColor(HexColor('#ef4444') if result.get('is_malware') else HexColor('#14b8a6'))
    c.roundRect(40, y - 10, (width - 80) * max(0, min(1, confidence_pct / 100)), 14, 7, fill=1, stroke=0)
    c.setFillColor(HexColor('#334155'))
    c.setFont('Helvetica', 9)
    c.drawRightString(width - 40, y + 7, f"{confidence_pct:.2f}%")
    y -= 30

    # Probability chart image
    y = ensure_space(y, 210)
    c.setFillColor(HexColor('#0f172a'))
    c.setFont('Helvetica-Bold', 12)
    c.drawString(40, y, 'Probability Analytics')
    y -= 8
    prob_chart = create_probability_chart()
    c.drawImage(ImageReader(prob_chart), 36, y - 185, width=width - 72, height=180, preserveAspectRatio=True, mask='auto')
    y -= 196

    # Indicator chart image
    indicator_chart = create_indicator_chart()
    if indicator_chart:
        y = ensure_space(y, 205)
        c.setFillColor(HexColor('#0f172a'))
        c.setFont('Helvetica-Bold', 12)
        c.drawString(40, y, 'Behavioral Indicator Analysis')
        y -= 8
        c.drawImage(ImageReader(indicator_chart), 36, y - 180, width=width - 72, height=175, preserveAspectRatio=True, mask='auto')
        y -= 190

    # Insight points
    y = ensure_space(y, 70)
    c.setFillColor(HexColor('#0f172a'))
    c.setFont('Helvetica-Bold', 12)
    c.drawString(40, y, 'Analyst Insights')
    y -= 16
    c.setFont('Helvetica', 10)
    insight_lines = [
        f"Primary predicted class is {result.get('malware_type', 'Unknown')} with {confidence_pct:.2f}% confidence.",
        'Probability spread across classes can indicate model certainty and ambiguity zones.',
        'Behavioral indicator peaks highlight features that likely influenced this prediction.'
    ]
    for line in insight_lines:
        c.drawString(46, y, line)
        y -= 14

    # Recommendations timeline-style block
    y -= 4
    y = ensure_space(y, 170)
    c.setFillColor(HexColor('#0f172a'))
    c.setFont('Helvetica-Bold', 12)
    c.drawString(40, y, 'Recommended Action Plan')
    y -= 18
    c.setLineWidth(1)
    c.setStrokeColor(HexColor('#94a3b8'))
    c.line(52, y - 120, 52, y)
    c.setFont('Helvetica', 10)
    step_y = y
    for idx, recommendation in enumerate(result.get('recommendations', [])[:7], start=1):
        lines = wrap_text(recommendation, max_chars=84)
        needed = 14 * len(lines) + 14
        step_y = ensure_space(step_y, needed)
        c.setFillColor(HexColor('#0ea5a4'))
        c.circle(52, step_y - 4, 4, stroke=0, fill=1)
        c.setFillColor(HexColor('#0f172a'))
        c.setFont('Helvetica-Bold', 9)
        c.drawString(64, step_y, f"Step {idx}")
        c.setFont('Helvetica', 9)
        text_y = step_y - 11
        for line in lines:
            c.drawString(64, text_y, line)
            text_y -= 12
        step_y = text_y - 6

    # Declaration and signature block
    sig_y = ensure_space(step_y - 4, 120)
    c.setFillColor(HexColor('#0f172a'))
    c.setFont('Helvetica-Bold', 12)
    c.drawString(40, sig_y, 'Declaration')
    c.setFont('Helvetica', 9)
    c.drawString(40, sig_y - 16, 'I hereby declare that this report was generated by the MalwareGuard system for')
    c.drawString(40, sig_y - 28, 'educational malware analysis and project demonstration purposes.')

    c.setStrokeColor(HexColor('#64748b'))
    c.line(40, sig_y - 62, 220, sig_y - 62)
    c.line(280, sig_y - 62, 500, sig_y - 62)
    c.setFillColor(HexColor('#334155'))
    c.setFont('Helvetica', 8)
    c.drawString(40, sig_y - 74, 'Student/Analyst Signature')
    c.drawString(280, sig_y - 74, 'Guide/Reviewer Signature')

    c.setFillColor(HexColor('#334155'))
    c.setFont('Helvetica-Oblique', 9)
    c.drawString(40, 40, 'Generated by MalwareGuard | Advanced PDF Intelligence Format')

    c.save()
    buffer.seek(0)
    return buffer


def calculate_entropy(data):
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def extract_ascii_strings(data, min_length=4):
    strings = []
    current = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_length:
        strings.append(''.join(current))
    return strings


def count_pattern_matches(text, patterns):
    lower_text = text.lower()
    count = 0
    for pattern in patterns:
        if pattern.lower() in lower_text:
            count += 1
    return count


def parse_pe_info(data):
    info = {'section_count': 0, 'imports_count': 0, 'exports_count': 0}
    if len(data) < 0x40 or data[:2] != b'MZ':
        return info

    try:
        e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
        if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return info

        info['section_count'] = int.from_bytes(data[e_lfanew + 6:e_lfanew + 8], 'little')
        magic = int.from_bytes(data[e_lfanew + 24:e_lfanew + 26], 'little')
        if magic == 0x10b:
            data_dir_offset = e_lfanew + 24 + 96
        elif magic == 0x20b:
            data_dir_offset = e_lfanew + 24 + 112
        else:
            data_dir_offset = None

        if data_dir_offset and data_dir_offset + 16 <= len(data):
            import_rva = int.from_bytes(data[data_dir_offset:data_dir_offset + 4], 'little')
            export_rva = int.from_bytes(data[data_dir_offset + 8:data_dir_offset + 12], 'little')
            if import_rva:
                info['imports_count'] = 1
            if export_rva:
                info['exports_count'] = 1
    except Exception:
        pass

    return info


def determine_file_type(filename, data):
    ext = os.path.splitext(filename)[1].lower().strip('.')
    if ext:
        return ext
    if data[:2] == b'MZ':
        return 'exe'
    return 'unknown'


def compute_detection_score(features):
    score = 0.0
    score += min(1.0, features.get('suspicious_api_calls', 0) * 0.02)
    score += min(1.0, features.get('network_connections', 0) * 0.01)
    score += min(1.0, features.get('registry_changes', 0) * 0.01)
    score += min(1.0, features.get('process_injections', 0) * 0.4)
    score += min(1.0, features.get('code_obfuscation', 0) * 0.2)
    score += min(1.0, features.get('packer_detected', 0) * 0.4)
    score += min(1.0, features.get('anti_debug_techniques', 0) * 0.3)
    score += min(1.0, features.get('vm_detection', 0) * 0.3)
    score += min(1.0, features.get('encryption_usage', 0) * 0.2)
    score += min(1.0, features.get('persistence_mechanisms', 0) * 0.1)
    score += min(1.0, features.get('data_exfiltration', 0) * 0.2)
    score += min(1.0, features.get('privilege_escalation', 0) * 0.3)
    return round(min(1.0, score / 5.0), 4)


def extract_file_features(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    strings = extract_ascii_strings(data)
    text = ' '.join(strings)

    suspicious_apis = [
        'CreateRemoteThread', 'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'GetProcAddress',
        'LoadLibrary', 'OpenProcess', 'CreateProcess', 'NtCreateThreadEx', 'ZwCreateProcess', 'UrlDownloadToFile',
        'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'send', 'recv', 'connect', 'GetWindowsDirectory'
    ]
    api_names = [
        'CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'CopyFile', 'MoveFile', 'CreateProcess',
        'LoadLibrary', 'GetProcAddress', 'OpenProcess', 'WriteProcessMemory', 'InternetOpen', 'socket',
        'connect', 'send', 'recv', 'RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey'
    ]
    registry_terms = ['RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey', 'RegQueryValue', 'RegCloseKey']
    file_ops = ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'CopyFile', 'MoveFile', 'CreateDirectory']
    network_terms = ['http://', 'https://', 'ftp://', 'socket', 'connect', 'send', 'recv', 'InternetOpen', 'InternetConnect', 'HttpOpenRequest']
    vm_terms = ['VBOX', 'VMWARE', 'VirtualBox', 'qemu', 'Hyper-V', 'VBoxService']
    anti_debug_terms = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString', 'DebugActiveProcess']
    packer_terms = ['UPX', 'MPRESS', 'ASPACK', 'PECompact', 'Themida', 'VMProtect', 'MoleBox', 'Enigma']
    encryption_terms = ['AES', 'RSA', 'CryptAcquireContext', 'CryptDecrypt', 'CryptEncrypt', 'BCryptEncrypt']
    persistence_terms = ['RunOnce', 'Run', 'AppInit_DLLs', 'Winlogon', 'Image File Execution Options', 'Services.exe']
    privilege_terms = ['SeDebugPrivilege', 'AdjustTokenPrivileges', 'OpenProcessToken', 'CreateRestrictedToken']
    exfiltration_terms = ['ftp', 'http', 'POST', 'GET', 'upload', 'mailto', 'smtp']
    command_control_terms = ['C2', 'command-and-control', 'botnet', 'server', 'control', 'feeder', 'beacon']
    obfuscation_terms = ['pack', 'obfuscate', 'encrypted', 'compressed', 'scrambled', 'encoded']

    file_type = determine_file_type(os.path.basename(file_path), data)
    entropy = calculate_entropy(data)
    pe_info = parse_pe_info(data)

    api_calls_count = count_pattern_matches(text, api_names)
    suspicious_api_calls = count_pattern_matches(text, suspicious_apis)
    network_connections = count_pattern_matches(text, network_terms)
    unique_ips = len(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
    dns_requests = len(re.findall(r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|ru|cn|info|biz|io|gov|edu)\b", text, flags=re.IGNORECASE))
    registry_changes = count_pattern_matches(text, registry_terms)
    file_operations = count_pattern_matches(text, file_ops)
    process_injections = 1 if count_pattern_matches(text, suspicious_apis) > 0 else 0
    code_obfuscation = 1 if count_pattern_matches(text, obfuscation_terms) > 0 or entropy > 7.5 else 0
    packer_detected = 1 if count_pattern_matches(text, packer_terms) > 0 else 0
    anti_debug_techniques = 1 if count_pattern_matches(text, anti_debug_terms) > 0 else 0
    vm_detection = 1 if count_pattern_matches(text, vm_terms) > 0 else 0
    encryption_usage = 1 if count_pattern_matches(text, encryption_terms) > 0 else 0
    persistence_mechanisms = count_pattern_matches(text, persistence_terms)
    data_exfiltration = count_pattern_matches(text, exfiltration_terms)
    privilege_escalation = count_pattern_matches(text, privilege_terms)
    command_control_channels = count_pattern_matches(text, command_control_terms)
    signature_valid = 0
    detection_score = compute_detection_score({
        'suspicious_api_calls': suspicious_api_calls,
        'network_connections': network_connections,
        'registry_changes': registry_changes,
        'process_injections': process_injections,
        'code_obfuscation': code_obfuscation,
        'packer_detected': packer_detected,
        'anti_debug_techniques': anti_debug_techniques,
        'vm_detection': vm_detection,
        'encryption_usage': encryption_usage,
        'persistence_mechanisms': persistence_mechanisms,
        'data_exfiltration': data_exfiltration,
        'privilege_escalation': privilege_escalation,
        'command_control_channels': command_control_channels
    })

    cpu_usage_percent = min(100.0, entropy * 10 + network_connections * 0.5 + file_operations * 0.1)
    memory_usage_mb = min(2048.0, entropy * 10 + unique_ips * 2 + file_operations * 0.2)

    return {
        'file_type': file_type,
        'file_size_bytes': len(data),
        'entropy': entropy,
        'pe_features': pe_info['imports_count'] + pe_info['exports_count'] + pe_info['section_count'],
        'section_count': pe_info['section_count'],
        'imports_count': api_calls_count,
        'exports_count': pe_info['exports_count'],
        'api_calls_count': api_calls_count,
        'suspicious_api_calls': suspicious_api_calls,
        'network_connections': network_connections,
        'unique_ips': unique_ips,
        'dns_requests': dns_requests,
        'registry_changes': registry_changes,
        'file_operations': file_operations,
        'process_injections': process_injections,
        'code_obfuscation': code_obfuscation,
        'packer_detected': packer_detected,
        'anti_debug_techniques': anti_debug_techniques,
        'vm_detection': vm_detection,
        'encryption_usage': encryption_usage,
        'cpu_usage_percent': cpu_usage_percent,
        'memory_usage_mb': memory_usage_mb,
        'persistence_mechanisms': persistence_mechanisms,
        'command_control_channels': command_control_channels,
        'data_exfiltration': data_exfiltration,
        'privilege_escalation': privilege_escalation,
        'signature_valid': signature_valid,
        'detection_score': detection_score
    }


def get_risk_level(probability, is_malware, malware_type):
    """Determine risk level based on probability and malware type"""
    
    # If it's benign (clean), always return Very Low risk
    if not is_malware or malware_type == 'Benign':
        return "Very Low", "✅", "risk-very-low"
    
    # For malware, determine risk based on probability
    if probability >= 0.9:
        return "Critical", "🔴", "risk-critical"
    elif probability >= 0.7:
        return "High", "🟠", "risk-high"
    elif probability >= 0.5:
        return "Medium", "🟡", "risk-medium"
    elif probability >= 0.3:
        return "Low", "🟢", "risk-low"
    else:
        return "Very Low", "⚪", "risk-very-low"

def get_recommendations(malware_type, probability):
    """Get prevention and containment recommendations by malware family."""

    label = str(malware_type or "").strip()
    normalized = re.sub(r'[^a-z0-9]+', '_', label.lower()).strip('_')

    # Map different dataset/app label styles to one canonical family name.
    aliases = {
        'ransomware': 'ransomware',
        'trojan': 'trojan',
        'worm': 'worm',
        'spyware': 'spyware',
        'cryptominer': 'cryptominer',
        'coinminer': 'cryptominer',
        'rootkit': 'rootkit',
        'keylogger': 'keylogger',
        'banking_trojan': 'banking_trojan',
        'banker': 'banking_trojan',
        'adware': 'adware',
        'backdoor': 'backdoor',
        'benign': 'benign',
        'clean': 'benign'
    }

    malware_family = aliases.get(normalized, normalized)

    family_recommendations = {
        'ransomware': [
            "🔌 Immediately disconnect the infected device from Wi-Fi/LAN and shared drives",
            "💾 Recover files only from clean, offline backups after full remediation",
            "🚫 Do not pay ransom; preserve evidence and report the incident",
            "🧪 Run enterprise anti-ransomware and EDR scan in offline/safe mode",
            "🔐 Patch OS/software quickly and enforce MFA on all admin and VPN accounts",
            "🧱 Segment network access to block lateral movement"
        ],
        'trojan': [
            "🛑 Isolate the system and terminate suspicious processes with EDR/Task Manager",
            "🔍 Perform a full antivirus plus anti-malware scan (not quick scan)",
            "🔑 Rotate passwords for email, cloud, VPN, and system admin accounts",
            "📥 Remove unknown startup items, scheduled tasks, and recently installed apps",
            "🧰 Apply OS and browser updates and disable unauthorized remote tools",
            "📜 Review login history for account misuse"
        ],
        'worm': [
            "🌐 Disconnect affected endpoints from the network immediately",
            "🧭 Block suspicious ports/SMB/RDP traffic on firewall and IDS",
            "🔄 Patch all hosts quickly, especially systems with known worm exploits",
            "🧱 Enforce network segmentation and least-privilege file sharing",
            "📊 Monitor east-west traffic for abnormal scan/spread behavior",
            "🧼 Reimage heavily infected machines before reconnecting"
        ],
        'spyware': [
            "🔐 Change passwords from a clean device and enable MFA everywhere",
            "🧽 Clear browser cookies/sessions and revoke untrusted app permissions",
            "📱 Check mobile devices and linked accounts for same compromise signs",
            "🛡️ Run anti-spyware scan and remove suspicious browser extensions",
            "🧾 Review bank/email/cloud activity for unauthorized actions",
            "🔒 Restrict camera/microphone/location permissions to trusted apps only"
        ],
        'cryptominer': [
            "⛔ Stop unauthorized mining processes/services and isolate the host",
            "🌡️ Check sustained high CPU/GPU use and overheating signs",
            "🗂️ Remove malicious startup entries, containers, and scheduled jobs",
            "🔐 Rotate cloud/API keys and wallet-related credentials",
            "🧱 Block outbound mining pool domains/IPs on firewall/DNS",
            "📈 Set alerts for abnormal compute and power usage spikes"
        ],
        'rootkit': [
            "🧯 Assume deep compromise and isolate the endpoint from all networks",
            "🧪 Use trusted boot media and rootkit detection tools for verification",
            "💿 Reinstall OS from known-good image if integrity is doubtful",
            "🔒 Enable Secure Boot/TPM and firmware password protections",
            "🔑 Rotate all credentials that were used on the infected machine",
            "📦 Restore only verified-clean data and applications"
        ],
        'keylogger': [
            "⌨️ Stop using the infected machine for credentials until cleaned",
            "🔑 Change all passwords from another clean device immediately",
            "🛡️ Enable MFA for email, banking, cloud, and social accounts",
            "🧩 Remove suspicious keyboard hooks/startup entries and unknown software",
            "📨 Watch for account takeover alerts and unusual login attempts",
            "🔒 Use password manager autofill to reduce typed credential exposure"
        ],
        'banking_trojan': [
            "🏦 Contact your bank/fraud team immediately and report compromise",
            "💳 Freeze or replace cards and reset online banking credentials",
            "📲 Enable transaction alerts and daily spending notifications",
            "🧾 Review recent transactions and dispute unknown operations",
            "🔐 Use a clean device only for financial logins until remediation",
            "🚫 Avoid clicking finance-themed links/attachments from email or SMS"
        ],
        'adware': [
            "🗑️ Uninstall suspicious apps and bundled software from Control Panel",
            "🌐 Reset browser home/search settings and remove unknown extensions",
            "🧹 Clear browser cache/notifications and revoke push permissions",
            "🛡️ Run anti-adware cleanup and PUP detection tools",
            "🧭 Download software only from official vendor websites",
            "⚙️ Disable auto-installers and optional bundled offers"
        ],
        'backdoor': [
            "🔌 Isolate the endpoint/server and block all remote control channels",
            "🔐 Rotate system, SSH/RDP, database, and API credentials",
            "🧱 Restrict inbound access with strict firewall and allow-list rules",
            "🕵️ Audit persistence mechanisms (services, tasks, registry, startup)",
            "📦 Rebuild compromised systems from clean images when possible",
            "📡 Monitor for C2 callbacks and unusual outbound beacon traffic"
        ],
        'benign': [
            "✅ No malware detected in this sample",
            "🔄 Keep OS, browser, and security tools updated",
            "🛡️ Keep real-time protection and firewall enabled",
            "💾 Maintain regular offline backups of important data",
            "📧 Avoid unknown email attachments and untrusted links",
            "🔑 Use strong unique passwords and MFA"
        ]
    }

    recommendations = family_recommendations.get(malware_family)
    if recommendations:
        if malware_family != 'benign' and probability >= 0.9:
            return [
                "🚨 High-confidence threat detected. Isolate the host immediately before cleanup."
            ] + recommendations
        return recommendations

    return [
        "⚠️ Unknown malware family detected: isolate the device immediately",
        "🛡️ Run a complete antivirus/EDR scan and remove suspicious artifacts",
        "🔄 Update OS and all security-critical software",
        "🔐 Rotate credentials used on this system",
        "💾 Restore from clean backups if system integrity is uncertain"
    ]

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    """Prediction page"""
    if not load_model():
        flash('Model not trained yet. Please train the model first.', 'warning')
        return redirect(url_for('train'))
    
    if request.method == 'POST':
        try:
            # Get uploaded file if present
            uploaded_file = request.files.get('sample_file')
            features = {}

            if uploaded_file and uploaded_file.filename != '':
                filename = secure_filename(uploaded_file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded_file.save(filepath)
                features = extract_file_features(filepath)
            else:
                # Collect all features from form
                for col in feature_columns:
                    value = request.form.get(col)
                    if value is not None and value != '':
                        try:
                            features[col] = float(value)
                        except:
                            features[col] = value
                    else:
                        features[col] = 0

            # Create dataframe
            input_df = pd.DataFrame([features])
            
            # Encode categorical features
            for col, encoder in label_encoders.items():
                if col in input_df.columns:
                    try:
                        input_df[col] = encoder.transform(input_df[col].astype(str))
                    except:
                        input_df[col] = 0
            
            # Ensure all feature columns are present
            for col in feature_columns:
                if col not in input_df.columns:
                    input_df[col] = 0
            
            # Reorder columns to match training
            input_df = input_df[feature_columns]
            
            # Scale features
            input_scaled = scaler.transform(input_df)
            
            # Make prediction
            if is_multiclass:
                predictions = model.predict(input_scaled)
                predicted_class_idx = np.argmax(predictions[0])
                malware_type = target_encoder.inverse_transform([predicted_class_idx])[0]
                probability = float(np.max(predictions[0]))
                
                # Determine if it's malware (not Benign)
                is_malware = malware_type != 'Benign'
                
                # Get risk level (pass is_malware flag)
                risk_level, risk_icon, risk_class = get_risk_level(probability, is_malware, malware_type)
                recommendations = get_recommendations(malware_type, probability)
                
                result = {
                    'malware_type': malware_type,
                    'probability': f"{probability:.2%}",
                    'probability_raw': probability,
                    'risk_level': risk_level,
                    'risk_icon': risk_icon,
                    'risk_class': risk_class,
                    'recommendations': recommendations,
                    'is_malware': is_malware,
                    'all_probabilities': {target_encoder.inverse_transform([i])[0]: float(predictions[0][i]) 
                                         for i in range(len(predictions[0]))}
                }
            else:
                # Binary classification
                prediction = float(model.predict(input_scaled)[0][0])
                is_malware = prediction > 0.5
                malware_type = 'Malware' if is_malware else 'Benign'
                probability = prediction if is_malware else 1 - prediction
                
                # Get risk level (pass is_malware flag)
                risk_level, risk_icon, risk_class = get_risk_level(probability, is_malware, malware_type)
                recommendations = get_recommendations(malware_type, probability)
                
                result = {
                    'malware_type': malware_type,
                    'probability': f"{probability:.2%}",
                    'probability_raw': probability,
                    'risk_level': risk_level,
                    'risk_icon': risk_icon,
                    'risk_class': risk_class,
                    'recommendations': recommendations,
                    'is_malware': is_malware,
                    'prediction_score': prediction
                }

            global latest_report_cache

            result['generated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            result['incident_id'] = f"MG-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
            result['top_indicators'] = extract_top_indicators(features)

            # Persist last report snapshot for PDF download.
            latest_report_cache = make_json_safe(result)
            session['latest_report'] = latest_report_cache
            
            return render_template('result.html', result=result, features=features)
            
        except Exception as e:
            flash(f'Error during prediction: {str(e)}', 'error')
            return redirect(request.url)
    
    # GET request - show prediction form with sample values
    return render_template('predict.html', features=feature_columns, sample_values=SAMPLE_VALUES)

@app.route('/api/sample/<sample_type>')
def get_sample(sample_type):
    """API endpoint to get sample values"""
    if sample_type in SAMPLE_VALUES:
        return jsonify({
            'success': True,
            'sample': SAMPLE_VALUES[sample_type]
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Sample not found'
        }), 404

@app.route('/api/predict', methods=['POST'])
def api_predict():
    """API endpoint for predictions"""
    if not load_model():
        return jsonify({'error': 'Model not trained'}), 400
    
    try:
        data = request.get_json()
        
        # Create dataframe from JSON
        input_df = pd.DataFrame([data])
        
        # Process features
        for col, encoder in label_encoders.items():
            if col in input_df.columns:
                input_df[col] = encoder.transform(input_df[col].astype(str))
        
        # Ensure all features present
        for col in feature_columns:
            if col not in input_df.columns:
                input_df[col] = 0
        
        input_df = input_df[feature_columns]
        input_scaled = scaler.transform(input_df)
        
        # Make prediction
        if is_multiclass:
            predictions = model.predict(input_scaled)
            predicted_class_idx = np.argmax(predictions[0])
            malware_type = target_encoder.inverse_transform([predicted_class_idx])[0]
            probability = float(np.max(predictions[0]))
            is_malware = malware_type != 'Benign'
        else:
            prediction = float(model.predict(input_scaled)[0][0])
            is_malware = prediction > 0.5
            malware_type = 'Malware' if is_malware else 'Benign'
            probability = prediction if is_malware else 1 - prediction
        
        risk_level, risk_icon, _ = get_risk_level(probability, is_malware, malware_type)
        
        return jsonify({
            'success': True,
            'malware_type': malware_type,
            'probability': probability,
            'risk_level': risk_level,
            'risk_icon': risk_icon,
            'is_malware': is_malware
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/train', methods=['GET', 'POST'])
def train():
    """Training page"""
    if request.method == 'POST':
        try:
            if 'dataset' not in request.files:
                flash('No file uploaded', 'error')
                return redirect(request.url)
            
            file = request.files['dataset']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(request.url)
            
            if file:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                from trainmodel import train_malware_model
                
                flash('Training started... This may take a few minutes.', 'info')
                
                try:
                    detector, accuracy, report, cm, auc_score = train_malware_model(filepath)
                    load_model()
                    flash(f'Training completed successfully! Accuracy: {accuracy:.2%}', 'success')
                    return redirect(url_for('results'))
                    
                except Exception as e:
                    flash(f'Error during training: {str(e)}', 'error')
                    return redirect(request.url)
                
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('train.html')

@app.route('/results')
def results():
    """Show training results"""
    training_img = os.path.exists('static/images/training_history.png')
    cm_img = os.path.exists('static/images/confusion_matrix.png')
    roc_img = os.path.exists('static/images/roc_curve.png')
    
    return render_template('results.html', 
                         training_img=training_img,
                         cm_img=cm_img,
                         roc_img=roc_img)


@app.route('/report/pdf')
def download_report_pdf():
    """Download the latest prediction report as PDF."""
    global latest_report_cache

    latest_report = session.get('latest_report') or latest_report_cache
    if not latest_report:
        flash('No report available yet. Run a prediction first.', 'warning')
        return redirect(url_for('predict'))

    try:
        pdf_buffer = generate_pdf_report(latest_report)
    except Exception as err:
        flash(f'Unable to generate PDF report: {str(err)}', 'error')
        return redirect(url_for('predict'))

    filename = f"malware_report_{latest_report.get('incident_id', 'latest')}.pdf"
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    load_model()
    app.run(debug=True, host='0.0.0.0', port=5000)