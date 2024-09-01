import json
import time
from display import display_help, display_chat_history, display_new_block, display_latest_block, display_constitution

def handle_command(command, node):
    if command == '/exit':
        node.running = False
        node.shutdown()
    elif command == '/help':
        display_help()
    elif command == '/ping':
        node.ping_peers()
    elif command == '/list':
        node.list_peers()
    elif command == '/blockchain':
        node.display_latest_block()
    elif command == '/history':
        node.display_chat_history()
    elif command == '/save':
        node.save_state()
    elif command == '/load':
        node.load_state()
    elif command == '/clear':
        node.clear_console()
    else:
        print("\033[91mUnknown command. Type /help for a list of commands.\033[0m")