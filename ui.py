import streamlit as st
import time
from streamlit_autorefresh import st_autorefresh
from scapy.all import get_working_ifaces

class StreamlitUI:
    def __init__(self, controller):
        self.controller = controller
        self.ss = st.session_state

        self.ss.setdefault("auto_refresh", 1000)
        self.ss.setdefault("bpf_filter", "")

    def render(self):
        st.set_page_config(
            page_title="Packet Viewer (Streamlit + Scapy)",
            layout="wide"
        )

        st.title("Packet Sniffer")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("PPS", f"{self.controller.get_pps():.1f}")

        with col2:
            st.metric("Sniffed", self.controller.get_sniffed_count())

        with col3:
            st.metric("Dropped", self.controller.get_dropped_count())
        
        # Start and stop buttons

        with st.sidebar:
            st.header("Capture Controls")
            st.divider()

            running = self.controller.is_running()

            interfaces = get_working_ifaces()

            if not interfaces:
                st.error("No network interfaces found.")
                selected_iface = None
            else:
                selected_iface = st.selectbox(
                    "Network Interface",
                    options=interfaces,
                    format_func=lambda iface: iface.description or iface.name,
                    disabled=running,
                    key="selected_interface"
                )

            # Start / Stop buttons
            col1, col2 = st.columns(2, gap="small")

            with col1:
                if st.button("Start", disabled=running or selected_iface is None):

                    try:
                        self.controller.start_capture(selected_iface)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to start capture: {e}")

            with col2:
                if st.button(
                    "Stop",
                    use_container_width=True,
                    disabled=not running
                ):
                    self.controller.stop_capture()
                    st.rerun()

            # Capture status
            if running:
                st.success("Capturing packets")
            else:
                st.error("Capture stopped")

            st.divider()


            # Refresh settings
            st.subheader("Settings")

            self.ss.auto_refresh = st.slider(
                "Refresh interval",
                min_value=500,
                max_value=10000,
                value=self.ss.auto_refresh,
                step=500,
                format="%d ms"
            )

            st.divider()

            # Export
            if st.button(
                "💾 Save PCAP",
                use_container_width=True
            ):
                filename = f"captured_packets_{int(time.time())}.pcap"
                self.controller.save_to_pcap(filename)
                st.success("PCAP saved!")

        # Empties the process queue inside the controller, parse and store the data
        self.controller.process_queue()

        # Gets all the stored packets
        packets = self.controller.get_packets()

        # Displays each packets summary as a row inside a table
        rows = [
            {"id": p["id"], **p["summary"]}
            for p in packets
        ]
        
        event = st.dataframe(
            rows[::-1],
            width="stretch",
            selection_mode="single-row",
            on_select="rerun",
            hide_index=True
            )

        if event.selection.rows:
            selected_index = event.selection.rows[0]
            selected_packet = rows[::-1][selected_index]
            details = self.controller.get_packet_details(selected_packet["id"])
            st.write("Selected packet:")

            for header, fields in details.items():
                with st.expander(header):
                    for key, value in fields.items():
                        st.write(f"**{key}**: {value}")

        if self.controller.is_running():
            st_autorefresh(
                interval=self.ss.auto_refresh,
                key="refresh"
            )