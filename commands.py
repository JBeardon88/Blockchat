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
        node.display_blockchain()
    elif command == '/history':
        node.display_chat_history()
    elif command == '/save':
        node.save_state()
    elif command == '/load':
        node.load_state()
    elif command == '/clear':
        node.clear_console()
    elif command == '/register':
        node.register_user()
    elif command.startswith('/login'):
        parts = command.split(' ', 1)
        if len(parts) < 2:
            print("\033[91mUsage: /login <seed_phrase>\033[0m")
        else:
            _, seed_phrase = parts
            node.login_user(seed_phrase)
    elif command.startswith('/pm'):
        parts = command.split(' ', 2)
        if len(parts) < 3:
            print("\033[91mUsage: /pm <username> <message>\033[0m")
        else:
            _, recipient, message = parts
            node.send_private_message(recipient, message)
    elif command == '/fullname':
        print(f"Full name: {node.get_fullname()}")
    else:
        print("\033[91mUnknown command. Type /help for a list of commands.\033[0m")