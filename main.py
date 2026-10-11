import streamlit as st
import queue

from sniffer import PacketSniffer
from parser import PacketParser
from storage import PacketStorage
from controller import PacketController
from ui import StreamlitUI


def create_app():
    packet_queue = queue.Queue(maxsize=1000)
    
    sniffer = PacketSniffer(packet_queue)
    parser = PacketParser()
    storage = PacketStorage()

    controller = PacketController(
        sniffer, parser, storage, packet_queue
    )

    return StreamlitUI(controller)


if "app" not in st.session_state:
    st.session_state.app = create_app()

st.session_state.app.render()