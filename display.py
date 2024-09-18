import time
import json 
from encryption import decrypt_message, base64

def display_help():
    print("\033[93mAvailable commands:\033[0m")
    print("/exit - Exit the application")
    print("/help - Display this help message")
    print("/ping - Check the connection to peers")
    print("/list - List all connected peers")
    print("/blockchain - Display the latest block in the blockchain")
    print("/history - Display the chat history")
    print("/save - Save the current blockchain and peer list to disk")
    print("/load - Load the blockchain and peer list from disk")
    print("/clear - Clear the console")

def display_chat_history(chat_history, node):
    print("\n\033[93m--- Chat History ---\033[0m")
    for msg in chat_history:
        if isinstance(msg, dict):
            if msg.get('type') in ['private_message_key', 'private_message_content']:
                # Handle private message components
                sender = msg.get('sender', 'Unknown')
                recipient = msg.get('recipient', 'Unknown')
                if recipient == node.get_fullname() or sender == node.get_fullname():
                    if msg['type'] == 'private_message_key':
                        print(f"\033[95m[Private Key] From {sender}\033[0m")
                    else:
                        content = msg.get('content', 'No content')
                        timestamp = msg.get('timestamp', time.time())
                        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

                        # Decrypt the message if it's still encrypted and the user is the recipient
                        if sender in node.private_message_keys and recipient == node.get_fullname():
                            try:
                                encrypted_content_bytes = base64.b64decode(content)
                                message_symmetric_key = node.private_message_keys[sender]
                                decrypted_content = decrypt_message(encrypted_content_bytes, message_symmetric_key)
                                if isinstance(decrypted_content, bytes):
                                    decrypted_content = decrypted_content.decode('utf-8')
                                content = decrypted_content
                            except Exception as e:
                                print(f"\033[91mError decrypting message from {sender}: {e}\033[0m")
                                import traceback
                                traceback.print_exc()

                        # Display the private message in lavender
                        print(f"\033[38;5;183m[{time_str}] {sender} (Private): {content}\033[0m")
                # Remove the "[private message exchanged]" message for non-involved users
            elif 'username' in msg and 'content' in msg:
                # Handle regular chat messages
                username = msg['username']
                content = msg['content']
                timestamp = msg.get('timestamp', time.time())
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
                if '.' in username:
                    print(f"\033[95m[{time_str}] \033[3m{username}\033[0m: {content}")  # Pink italics for registered users
                else:
                    print(f"\033[94m[{time_str}] {username}\033[0m: {content}")
            elif msg.get('type') == 'system':
                # Handle system messages
                content = msg.get('content', 'System message')
                print(f"\033[92m{content}\033[0m")
        elif isinstance(msg, str):
            # Handle string messages (like old-style registration notifications)
            print(f"\033[92m{msg}\033[0m")
    print("\033[93m--------------------\033[0m")

def display_new_block(latest_block, symmetric_key):
    if not latest_block:
        return
    try:
        decrypted_data = decrypt_message(latest_block.data, symmetric_key)
    except Exception as e:
        decrypted_data = f"Error decrypting data: {e}"
    block_info = (
        f"\n\033[93m--- New Block Added ---\033[0m\n"
        f"Index: \033[96m{latest_block.index}\033[0m\n"
        f"Timestamp: \033[96m{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_block.timestamp))}\033[0m\n"
        f"Data: \033[96m{decrypted_data}\033[0m\n"
        f"Hash: \033[96m{latest_block.hash}\033[0m\n"
        f"Previous Hash: \033[96m{latest_block.previous_hash}\033[0m\n"
        f"--------------------\n"
    )
    print(block_info)

def display_latest_block(latest_block, symmetric_key):
    if not latest_block:
        print("\033[91mNo blocks in the chain yet.\033[0m")
    else:
        try:
            decrypted_data = decrypt_message(latest_block.data, symmetric_key)
        except Exception as e:
            decrypted_data = f"Error decrypting data: {e}"
        block_info = (
            f"\n\033[93m--- Latest Block ---\033[0m\n"
            f"Index: \033[96m{latest_block.index}\033[0m\n"
            f"Timestamp: \033[96m{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_block.timestamp))}\033[0m\n"
            f"Data: \033[96m{decrypted_data}\033[0m\n"
            f"Hash: \033[96m{latest_block.hash}\033[0m\n"
            f"Previous Hash: \033[96m{latest_block.previous_hash}\033[0m\n"
            f"--------------------\n"
        )
        print(block_info)

def display_constitution(constitution):
    print("\n\033[1m" + "=" * 50 + "\n" + constitution['title'] + "\n" + "=" * 50 + "\033[0m")
    print("\n\033[3m" + constitution['preamble'] + "\033[0m\n")
    for article in constitution['articles']:
        print(article)
    print("\n" + "=" * 50 + "\n")