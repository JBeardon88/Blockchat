import time
import json 
from encryption import decrypt_message

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

def display_chat_history(chat_history):
    print("\n--- Chat History ---")
    for msg in chat_history:
        if isinstance(msg, dict):
            print(f"\033[94m{msg['username']}\033[0m: {msg['content']}")
    print("--------------------")

def display_new_block(latest_block):
    if not latest_block:
        return
    try:
        decrypted_data = decrypt_message(latest_block.data)
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

def display_latest_block(latest_block):
    if not latest_block:
        print("\033[91mNo blocks in the chain yet.\033[0m")
    else:
        try:
            decrypted_data = decrypt_message(latest_block.data)
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