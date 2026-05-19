import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Setup canvas dimensions and background
fig, ax = plt.subplots(figsize=(11, 6), dpi=300)
ax.set_xlim(0, 11)
ax.set_ylim(0, 6)
ax.axis('off')

# Helper function to draw styled component boxes
def draw_box(ax, x, y, w, h, text, title, box_color, text_color='white'):
    # Draw main structural box
    rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1", 
                                  linewidth=1.5, edgecolor=box_color, facecolor=box_color)
    ax.add_patch(rect)
    # Add title string
    ax.text(x + w/2, y + h - 0.3, title, weight='bold', color=text_color, 
            fontsize=10, ha='center', va='center')
    # Add body text description
    ax.text(x + w/2, y + h/2 - 0.2, text, color=text_color, 
            fontsize=8.5, ha='center', va='center', style='italic')

# Helper function to draw directed data flow arrows
def draw_arrow(ax, x1, y1, x2, y2, label=""):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="->", color="#1e293b", lw=2))
    if label:
        ax.text((x1+x2)/2, ((y1+y2)/2)+0.15, label, fontsize=8, 
                color="#475569", weight='bold', ha='center')

# --- Render Pipeline Architecture Components ---

# 1. Network Traffic Source
draw_box(ax, 0.5, 2.2, 1.8, 1.4, "Loopback Interface\n(Raw Packet Frames)", "1. Traffic Ingestion", "#0284c7")

# 2. Signature Detection Layer
draw_box(ax, 3.2, 2.2, 2.0, 1.4, "Custom DDoS Rules\n& Signature Matching", "2. Snort 3 Engine", "#b91c1c")

# 3. Intelligent Classification Bridge
draw_box(ax, 6.0, 2.2, 2.0, 1.4, "ai_logic.py\n(Random Forest Core)", "3. ML Classifier", "#0f766e")

# 4. Central Management Console
draw_box(ax, 8.8, 2.2, 1.8, 1.4, "Streamlit Web UI\n(Live Threat Stream)", "4. SOC Dashboard", "#1e1b4b")

# --- Render Directional Data Flow Vectors ---
draw_arrow(ax, 2.4, 2.9, 3.1, 2.9, "Mirroring Data")
draw_arrow(ax, 5.3, 2.9, 5.9, 2.9, "Packet Metrics")
draw_arrow(ax, 8.1, 2.9, 8.7, 2.9, "Prediction Vectors")

# Main architectural chart headers
ax.text(5.5, 5.2, "Hybrid Network Intrusion Detection System (NIDS) Architectural Pipeline", 
        fontsize=13, weight='bold', color='#0f172a', ha='center')
ax.text(5.5, 4.8, "Bank Muscat Security Operations Blueprint - Structural Telemetry Flow", 
        fontsize=10, color='#64748b', ha='center', style='italic')

# Compile and export schematic view
plt.tight_layout()
plt.savefig('NIDS_Data_Flow.png', bbox_inches='tight', dpi=300)
print("[+] Architecture Diagram generated successfully as 'NIDS_Data_Flow.png'")
